#  Polkascan PRE Harvester
#
#  Copyright 2018-2020 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  tasks.py

import os, sys
from time import sleep

import celery
from celery.result import AsyncResult

import app.settings
from scalecodec.base import ScaleDecoder, ScaleBytes, RuntimeConfiguration

from sqlalchemy import create_engine, text, distinct
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql import func

from app.models.data import Block, Account, AccountInfoSnapshot, SearchIndex
from app.models.harvester import Status
from app.processors.converters import PolkascanHarvesterService, HarvesterCouldNotAddBlock, BlockAlreadyAdded, \
    BlockIntegrityError

from substrateinterface import SubstrateInterface

from app.settings import DB_CONNECTION, DEBUG, SUBSTRATE_RPC_URL, TYPE_REGISTRY, FINALIZATION_ONLY, TYPE_REGISTRY_FILE, LOG_LEVEL, LOG_FORMAT
import logging
logging.basicConfig(stream=sys.stdout, level=LOG_LEVEL, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

CELERY_BROKER = os.environ.get('CELERY_BROKER')
CELERY_BACKEND = os.environ.get('CELERY_BACKEND')

capp = celery.Celery('tasks', broker=CELERY_BROKER, backend=CELERY_BACKEND)

capp.conf.beat_schedule = {
    'check-head-10-seconds': {
        'task': 'app.tasks.start_harvester',
        'schedule': 10.0,
        'args': ()
    },
    'clean-up-blocks': {
        'task': 'app.tasks.clean_up_blocks',
        'schedule': 30.0,
        'args': ()
    },
    'check-missing-block': {
        'task': 'app.tasks.start_harvester',
        'schedule': 1800.0,
        'args': (True,)
    },
    'update-start-block-id': {
        'task': 'app.tasks.update_start_block_id',
        'schedule': 1800.0,
        'args': ()
    },
}

capp.conf.timezone = 'UTC'

@celery.signals.worker_ready.connect
def at_start(sender, **kwargs):
    logger.info('worker ready')
    with sender.app.connection() as conn:
        sender.app.send_task("app.tasks.update_start_block_id", connection=conn)
        sender.app.send_task("app.tasks.start_harvester", connection=conn, kwargs={'check_gaps': True})
        sender.app.send_task("app.tasks.clean_up_status", connection=conn)



class BaseTask(celery.Task):

    def __init__(self):
        self.metadata_store = {}

    def __call__(self, *args, **kwargs):
        self.engine = create_engine(DB_CONNECTION, echo=DEBUG, isolation_level="READ_UNCOMMITTED", pool_pre_ping=True, pool_size=30)
        session_factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        self.session = scoped_session(session_factory)

        return super().__call__(*args, **kwargs)

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        if hasattr(self, 'session'):
            self.session.remove()
        if hasattr(self, 'engine'):
            self.engine.engine.dispose()


@capp.task(base=BaseTask, bind=True)
def accumulate_block_recursive(self, block_hash, end_block_hash=None):
    logger.debug('accumulate_block_recursive: start: {}, end: {}'.format(block_hash, end_block_hash))

    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
    )

    harvester.metadata_store = self.metadata_store
    harvester.substrate.metadata_cache = self.metadata_store

    # If metadata store isn't initialized yet, perform some tests
    # if not harvester.metadata_store:
    #     print('Init: create entrypoints')
    #     # Check if blocks exists
    #     max_block_id = self.session.query(func.max(Block.id)).one()[0]
    #
    #     if not max_block_id:
    #         # Speed up accumulating by creating several entry points
    #         substrate = SubstrateInterface(
    #             url=SUBSTRATE_RPC_URL,
    #             type_registry_preset=app.settings.TYPE_REGISTRY,
    #             runtime_config=RuntimeConfiguration()
    #         )
    #         block_nr = substrate.get_block_number(block_hash)
    #         if block_nr > 100:
    #             for entry_point in range(0, block_nr, block_nr // 4)[1:-1]:
    #                 entry_point_hash = substrate.get_block_hash(entry_point)
    #                 accumulate_block_recursive.delay(entry_point_hash)

    block = None
    max_sequenced_block_id = False

    add_count = 0

    try:
        for nr in range(0, 20):
            if not block or block.id > 0:
                # Process block
                block = harvester.add_block(block_hash)
                self.session.commit()

                add_count += 1
                logger.debug('accumulate_block_recursive: added block: {}, {}'.format(block_hash, block.id))

                # Break loop if targeted end block hash is reached
                if block_hash == end_block_hash or block.id == 0:
                    break

                # Continue with parent block hash
                block_hash = block.parent_hash

        # Update persistent metadata store in Celery task
        self.metadata_store = harvester.metadata_store

        if block_hash != end_block_hash and block and block.id > 0:
            accumulate_block_recursive.delay(block.parent_hash, end_block_hash)

    except BlockAlreadyAdded as e:
        logger.warning('accumulate_block_recursive: block already added: {}'.format(block_hash))
    # except IntegrityError as e:
    #     print('. Skipped duplicate {} '.format(block_hash))
    except Exception as exc:
        logger.error('accumulate_block_recursive: error adding block: {}, {}'.format(block_hash, exc))
        raise HarvesterCouldNotAddBlock(block_hash) from exc

    return {
        'result': '{} blocks added'.format(add_count),
        'lastAddedBlockHash': block_hash,
        'sequencerStartedFrom': max_sequenced_block_id
    }


@capp.task(base=BaseTask, bind=True)
def start_sequencer(self):
    sequencer_task = Status.get_status(self.session, 'SEQUENCER_TASK_ID')
    logger.debug('start_sequencer task {}'.format(sequencer_task.value))
    if sequencer_task.value:
        task_result = AsyncResult(sequencer_task.value)
        try:
            task_ready = task_result.ready()
        except TypeError as e:
            logger.warning('start_sequencer TypeError: {}'.format(e))
            task_ready = True
        if not task_result or task_ready:
            logger.debug('start_sequencer task_ready {}'.format(task_ready))
            sequencer_task.value = None
            sequencer_task.save(self.session)
            self.session.commit()

    if sequencer_task.value is None:
        sequencer_task.value = self.request.id
        logger.debug('start_sequencer none to value: {}'.format(self.request.id))
        sequencer_task.save(self.session)

        harvester = PolkascanHarvesterService(
            db_session=self.session,
            type_registry=TYPE_REGISTRY,
            type_registry_file=TYPE_REGISTRY_FILE
        )
        try:
            logger.debug('start_sequencer outer')
            result = harvester.start_sequencer()
        except BlockIntegrityError as e:
            result = {'result': str(e)}
            logger.warning('start_sequencer value to none: {}, {}'.format(sequencer_task.value, e))
        sequencer_task.value = None
        sequencer_task.save(self.session)

        self.session.commit()

        # Check if analytics data need to be generated
        # start_generate_analytics.delay()

        return result
    else:
        logger.debug('start_sequencer not none {}'.format(sequencer_task.value))
        return {'result': 'Sequencer already running'}


# @capp.task(base=BaseTask, bind=True)
# def rebuilding_search_index(self, search_index_id=None, truncate=False):
#     if truncate:
#         # Clear search index table
#         self.session.execute('delete from analytics_search_index where index_type_id={}'.format(search_index_id))
#         self.session.commit()

#     harvester = PolkascanHarvesterService(
#         db_session=self.session,
#         type_registry=TYPE_REGISTRY,
#         type_registry_file=TYPE_REGISTRY_FILE
#     )
#     harvester.rebuild_search_index()

#     return {'result': 'index rebuilt'}


@capp.task(base=BaseTask, bind=True)
def start_harvester(self, check_gaps=False):

    substrate = SubstrateInterface(
        url=SUBSTRATE_RPC_URL,
        type_registry_preset=app.settings.TYPE_REGISTRY,
        runtime_config=RuntimeConfiguration()
    )

    block_sets = []
    start_block_id = Status.get_status(self.session, 'START_BLOCK_ID')
    if check_gaps and start_block_id.value is not None:
        # Check for gaps between already harvested blocks and try to fill them first
        remaining_sets_result = Block.get_missing_block_ids(self.session, start_block_id.value)
        for block_set in remaining_sets_result:
            # Get start and end block hash
            end_block_hash = substrate.get_block_hash(int(block_set['block_from']))
            start_block_hash = substrate.get_block_hash(int(block_set['block_to']))
            # Start processing task
            accumulate_block_recursive.delay(start_block_hash, end_block_hash)
            block_sets.append({
                'start_block_hash': start_block_hash,
                'end_block_hash': end_block_hash
            })
            logger.info('check gaps start_block_hash: {}, end_block_hash: {}, block_from: {}, block_to: {}'.format(start_block_hash, end_block_hash, block_set['block_from'], block_set['block_to']))

    # Start sequencer
    sequencer_task = start_sequencer.delay()

    # Continue from current (finalised) head
    if FINALIZATION_ONLY == 1:
        start_block_hash = substrate.get_chain_finalised_head()
    else:
        start_block_hash = substrate.get_chain_head()

    end_block_hash = None

    accumulate_block_recursive.delay(start_block_hash, end_block_hash)
    logger.debug('accumulate_block_recursive--->>> after', start_block_hash, end_block_hash)

    block_sets.append({
        'start_block_hash': start_block_hash,
        'end_block_hash': end_block_hash
    })

    return {
        'result': 'Harvester job started',
        'block_sets': block_sets,
        'sequencer_task_id': sequencer_task.task_id
    }


@capp.task(base=BaseTask, bind=True)
def start_generate_analytics(self):
    self.session.execute('CALL generate_analytics_data()')
    self.session.commit()
    return {'status': 'OK'}


@capp.task(base=BaseTask, bind=True)
def rebuild_search_index(self, start, end):
    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
    )
    harvester.rebuild_search_index(start, end)

    return {'result': 'search index rebuilt'}


@capp.task(base=BaseTask, bind=True)
def rebuild_account_info_snapshot(self, index):
    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
    )

    # self.session.execute('truncate table {}'.format(AccountInfoSnapshot.__tablename__))
    self.session.execute('DELETE FROM {} WHERE block_id > {} AND block_id <= {}'.format(AccountInfoSnapshot.__tablename__, \
        index * 10000, (index+1) * 10000))

    for account_id, block_id in self.session.query(SearchIndex.account_id, SearchIndex.block_id).filter(
            SearchIndex.block_id >= app.settings.BALANCE_SYSTEM_ACCOUNT_MIN_BLOCK,
            SearchIndex.block_id > index * 10000,
            SearchIndex.block_id <= (index+1) * 10000
    ).order_by('block_id').group_by(SearchIndex.account_id, SearchIndex.block_id).yield_per(1000):

        if block_id % app.settings.BALANCE_FULL_SNAPSHOT_INTERVAL != 0:
            harvester.create_balance_snapshot(block_id, account_id)
            self.session.commit()

    harvester.create_full_balance_snaphot((index+1) * 10000)
    self.session.commit()

    # set balances according to most recent snapshot
    account_info = self.session.execute("""
            select
               a.account_id,
               a.balance_total,
               a.balance_free,
               a.balance_reserved,
               a.nonce
        from
             data_account_info_snapshot as a
        inner join (
            select
                account_id, max(block_id) as max_block_id
            from data_account_info_snapshot
            group by account_id
        ) as b
        on a.account_id = b.account_id and a.block_id = b.max_block_id
        """)

    for account_id, balance_total, balance_free, balance_reserved, nonce in account_info:
        Account.query(self.session).filter_by(id=account_id).update(
            {
                Account.balance_total: balance_total,
                Account.balance_free: balance_free,
                Account.balance_reserved: balance_reserved,
                Account.nonce: nonce,
            }, synchronize_session='fetch'
        )
    self.session.commit()


    return {'result': 'account info snapshots rebuilt'}


@capp.task(base=BaseTask, bind=True)
def balance_snapshot(self, account_id=None, block_start=1, block_end=None, block_ids=None):
    if account_id:
        accounts = [account_id]
    else:
        accounts = [account.id for account in Account.query(self.session)]

    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
    )

    if block_ids:
        block_range = block_ids
    else:

        if block_end is None:
            # Set block end to chaintip
            substrate = SubstrateInterface(
                url=SUBSTRATE_RPC_URL,
                runtime_config=RuntimeConfiguration(),
                type_registry_preset=app.settings.TYPE_REGISTRY
            )
            block_end = substrate.get_block_number(substrate.get_chain_finalised_head())
            logger.debug('DEEPER--->>>  balance_snapshot substrate.close')
            substrate.close()

        block_range = range(block_start, block_end + 1)

    for block_id in block_range:
        for account in accounts:
            harvester.create_balance_snapshot(block_id, account)
            self.session.commit()

    return {
        'message': 'Snapshop created',
        'account_id': account_id,
        'block_start': block_start,
        'block_end': block_end,
        'block_ids': block_ids
    }


@capp.task(base=BaseTask, bind=True)
def update_balances_in_block(self, block_id):
    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
    )

    harvester.create_full_balance_snaphot(block_id)
    self.session.commit()

    harvester.update_account_balances()
    self.session.commit()

    return 'Snapshot created for block {}'.format(block_id)


@capp.task(base=BaseTask, bind=True)
def clean_up_status(self):
    sequencer_task = Status.get_status(self.session, 'SEQUENCER_TASK_ID')
    logger.info('clean up sequencer_task: {}'.format(sequencer_task.value))
    sequencer_task.value = None
    sequencer_task.save(self.session)
    # reset INTEGRITY_HEAD
    integrity_head = Status.get_status(self.session, 'INTEGRITY_HEAD')
    logger.info('clean up integrity_head: {}'.format(integrity_head.value))
    integrity_head.value = None
    integrity_head.save(self.session)
    self.session.commit()
    return {'result': 'OK'}

@capp.task(base=BaseTask, bind=True)
def update_start_block_id(self):
    substrate = SubstrateInterface(
                url=SUBSTRATE_RPC_URL,
                runtime_config=RuntimeConfiguration(),
                type_registry_preset=app.settings.TYPE_REGISTRY
            )
    block_id = substrate.get_block_number(substrate.get_chain_head())
    seconds_per_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    days_ago_in_seconds = int(app.settings.BLOCK_HISTORY_PERIOD[:-1]) * seconds_per_unit[app.settings.BLOCK_HISTORY_PERIOD[-1]]
    if days_ago_in_seconds <= 0:
        raise Exception('Invalid block history period: {}'.format(app.settings.BLOCK_HISTORY_PERIOD))
    days_ago_block_id = max(int(block_id - days_ago_in_seconds / 5), 1)
    logger.info('update_start_block_id, period: {}, head block id: {}, days ago block id: {}, total blocks: {}'.format(app.settings.BLOCK_HISTORY_PERIOD, block_id, days_ago_block_id, block_id - days_ago_block_id))
    start_block_id = Status.get_status(self.session, 'START_BLOCK_ID')
    start_block_id.value = days_ago_block_id
    start_block_id.save(self.session)
    self.session.commit()

    return {'result': 'OK'}

@capp.task(base=BaseTask, bind=True)
def clean_up_blocks(self):
    start_block_id = Status.get_status(self.session, 'START_BLOCK_ID')
    if start_block_id.value is None:
        return {'result': 'Waiting for start block id'}
    start_block_id = int(start_block_id.value)
    deleting_blocks = self.session.query(Block.hash).filter(Block.id < start_block_id).limit(100)
    total_blocks = deleting_blocks.count()
    logger.info('clean_up_blocks, start block id: {}, going to delete {} blocks'.format(start_block_id, total_blocks))
    harvester = PolkascanHarvesterService(
        db_session=self.session,
        type_registry=TYPE_REGISTRY,
        type_registry_file=TYPE_REGISTRY_FILE
        )
    for block in deleting_blocks:
        harvester.remove_block(block.hash, True)
        self.session.commit()
    logger.info('clean_up_blocks, finished. deleted {} blocks'.format(total_blocks))
    return {'result': 'OK', 'total_blocks': total_blocks}
