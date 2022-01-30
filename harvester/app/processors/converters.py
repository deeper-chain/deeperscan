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
#  converters.py
import json
import logging

import math
import datetime
import dateutil.parser
import pytz

from app import settings

from sqlalchemy import func, distinct
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from app.models.harvester import Status
from app.processors import NewSessionEventProcessor, Log, SlashEventProcessor, BalancesTransferProcessor
from scalecodec.base import ScaleBytes, ScaleDecoder, RuntimeConfiguration
from scalecodec.exceptions import RemainingScaleBytesNotEmptyException
from scalecodec.types import Extrinsic as ExtrinsicsDecoder

from app.processors.base import BaseService, ProcessorRegistry
from scalecodec.type_registry import load_type_registry_file
from substrateinterface import SubstrateInterface, logger
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.hasher import xxh128

from app.models.data import Extrinsic, Block, Event, Runtime, RuntimeModule, RuntimeCall, RuntimeCallParam, \
    RuntimeEvent, RuntimeEventAttribute, RuntimeType, RuntimeStorage, BlockTotal, RuntimeConstant, AccountAudit, \
    AccountIndexAudit, ReorgBlock, ReorgExtrinsic, ReorgEvent, ReorgLog, RuntimeErrorMessage, Account, \
    AccountInfoSnapshot, SearchIndex, BlockMissing


if settings.DEBUG:
    # Set Logger level to Debug
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    logger.addHandler(ch)


class HarvesterCouldNotAddBlock(Exception):
    pass


class BlockAlreadyAdded(Exception):
    pass


class BlockIntegrityError(Exception):
    pass


class PolkascanHarvesterService(BaseService):

    def __init__(self, db_session, type_registry='default', type_registry_file=None):
        self.db_session = db_session

        if type_registry_file:
            custom_type_registry = load_type_registry_file(type_registry_file)
        else:
            custom_type_registry = 'default'

        self.substrate = SubstrateInterface(
            url=settings.SUBSTRATE_RPC_URL,
            type_registry=custom_type_registry,
            type_registry_preset=type_registry,
            runtime_config=RuntimeConfiguration()
        )
        self.metadata_store = {}

    def process_genesis(self, block):
        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> PolkascanHarvesterService process_genesis block.hash={}".format(block.hash))

        # Set block time of parent block
        child_block = Block.query(self.db_session).filter_by(parent_hash=block.hash).first()
        if child_block.datetime:
            block.set_datetime(child_block.datetime)

        # Retrieve genesis accounts
        if settings.get_versioned_setting('SUBSTRATE_STORAGE_INDICES', block.spec_version_id) == 'Accounts':

            # Get accounts from storage keys
            storage_key_prefix = self.substrate.generate_storage_hash(
                storage_module='System',
                storage_function='Account'
            )

            rpc_result = self.substrate.rpc_request(
                'state_getKeys',
                [storage_key_prefix, block.hash]
            ).get('result')
            # Extract accounts from storage key
            genesis_accounts = [storage_key[-64:] for storage_key in rpc_result if len(storage_key) == 162]

            for account_id in genesis_accounts:
                account_audit = AccountAudit(
                    account_id=account_id,
                    block_id=block.id,
                    extrinsic_idx=None,
                    event_idx=None,
                    type_id=settings.ACCOUNT_AUDIT_TYPE_NEW
                )

                account_audit.save(self.db_session)

        elif settings.get_versioned_setting('SUBSTRATE_STORAGE_INDICES', block.spec_version_id) == 'EnumSet':

            genesis_account_page_count = self.substrate.get_runtime_state(
                module="Indices",
                storage_function="NextEnumSet",
                block_hash=block.hash
            ).get('result', 0)

            # Get Accounts on EnumSet
            block.count_accounts_new = 0
            block.count_accounts = 0

            for enum_set_nr in range(0, genesis_account_page_count + 1):

                genesis_accounts = self.substrate.get_runtime_state(
                    module="Indices",
                    storage_function="EnumSet",
                    params=[enum_set_nr],
                    block_hash=block.hash
                ).get('result')

                if genesis_accounts:
                    block.count_accounts_new += len(genesis_accounts)
                    block.count_accounts += len(genesis_accounts)

                    for idx, account_id in enumerate(genesis_accounts):
                        account_audit = AccountAudit(
                            account_id=account_id.replace('0x', ''),
                            block_id=block.id,
                            extrinsic_idx=None,
                            event_idx=None,
                            type_id=settings.ACCOUNT_AUDIT_TYPE_NEW
                        )

                        account_audit.save(self.db_session)

                        account_index_id = enum_set_nr * 64 + idx

                        account_index_audit = AccountIndexAudit(
                            account_index_id=account_index_id,
                            account_id=account_id.replace('0x', ''),
                            block_id=block.id,
                            extrinsic_idx=None,
                            event_idx=None,
                            type_id=settings.ACCOUNT_INDEX_AUDIT_TYPE_NEW
                        )

                        account_index_audit.save(self.db_session)

        block.save(self.db_session)

        # Add hardcoded account like treasury stored in settings
        for account_id in settings.SUBSTRATE_TREASURY_ACCOUNTS:
            account_audit = AccountAudit(
                account_id=account_id,
                block_id=block.id,
                extrinsic_idx=None,
                event_idx=None,
                data={'is_treasury': True},
                type_id=settings.ACCOUNT_AUDIT_TYPE_NEW
            )

            account_audit.save(self.db_session)

            if settings.DEEPER_DEBUG:
                print("DEEPER--->>> PolkascanHarvesterService SUBSTRATE_TREASURY_ACCOUNTS account_id={}".format(account_audit.account_id))

        # Check for sudo accounts
        try:
            # Update sudo key
            sudo_key = self.substrate.get_runtime_state(
                module='Sudo',
                storage_function='Key',
                block_hash=block.hash
            ).get('result')

            account_audit = AccountAudit(
                account_id=sudo_key.replace('0x', ''),
                block_id=block.id,
                extrinsic_idx=None,
                event_idx=None,
                data={'is_sudo': True},
                type_id=settings.ACCOUNT_AUDIT_TYPE_NEW
            )

            if settings.DEEPER_DEBUG:
                print("DEEPER--->>> PolkascanHarvesterService Sudo account_id={}".format(account_audit.account_id))

            account_audit.save(self.db_session)
        except ValueError:
            pass

        # Create initial session
        initial_session_event = NewSessionEventProcessor(
            block=block, event=Event(), substrate=self.substrate
        )

        if settings.get_versioned_setting('NEW_SESSION_EVENT_HANDLER', block.spec_version_id):
            initial_session_event.add_session(db_session=self.db_session, session_id=0)
        else:
            initial_session_event.add_session_old(db_session=self.db_session, session_id=0)

    def process_metadata(self, spec_version, block_hash):

        # Check if metadata already stored
        runtime = Runtime.query(self.db_session).get(spec_version)

        if runtime:

            if spec_version in self.substrate.metadata_cache:
                self.metadata_store[spec_version] = self.substrate.metadata_cache[spec_version]
            else:
                self.metadata_store[spec_version] = self.substrate.get_block_metadata(block_hash=block_hash)

        else:
            print('Metadata: CACHE MISS', spec_version)

            runtime_version_data = self.substrate.get_block_runtime_version(block_hash)

            self.db_session.begin(subtransactions=True)
            try:

                # Store metadata in database
                runtime = Runtime(
                    id=spec_version,
                    impl_name=runtime_version_data["implName"],
                    impl_version=runtime_version_data["implVersion"],
                    spec_name=runtime_version_data["specName"],
                    spec_version=spec_version,
                    json_metadata=str(self.substrate.metadata_decoder.data),
                    json_metadata_decoded=self.substrate.metadata_decoder.value,
                    apis=runtime_version_data["apis"],
                    authoring_version=runtime_version_data["authoringVersion"],
                    count_call_functions=0,
                    count_events=0,
                    count_modules=len(self.substrate.metadata_decoder.pallets),
                    count_storage_functions=0,
                    count_constants=0,
                    count_errors=0
                )

                runtime.save(self.db_session)

                print('store version to db', self.substrate.runtime_version)

                for module_index, module in enumerate(self.substrate.metadata_decoder.pallets):

                    if hasattr(module, 'index'):
                        module_index = module.index

                    # Check if module exists
                    if RuntimeModule.query(self.db_session).filter_by(
                        spec_version=spec_version,
                        module_id=module.get_identifier()
                    ).count() == 0:
                        module_id = module.get_identifier()
                    else:
                        module_id = '{}_1'.format(module.get_identifier())

                    # Storage backwards compt check
                    if module.storage and isinstance(module.storage, list):
                        storage_functions = module.storage
                    elif module.storage and isinstance(getattr(module.storage, 'value'), dict):
                        storage_functions = module.storage.items
                    else:
                        storage_functions = []

                    runtime_module = RuntimeModule(
                        spec_version=spec_version,
                        module_id=module_id,
                        prefix='', #module.prefix,
                        name=module.name,
                        count_call_functions=len(module.calls or []),
                        count_storage_functions=len(storage_functions),
                        count_events=len(module.events or []),
                        count_constants=len(module.constants or []),
                        count_errors=len(module.errors or []),
                    )
                    runtime_module.save(self.db_session)

                    # Update totals in runtime
                    runtime.count_call_functions += runtime_module.count_call_functions
                    runtime.count_events += runtime_module.count_events
                    runtime.count_storage_functions += runtime_module.count_storage_functions
                    runtime.count_constants += runtime_module.count_constants
                    runtime.count_errors += runtime_module.count_errors

                    if len(module.calls or []) > 0:
                        for idx, call in enumerate(module.calls):
                            runtime_call = RuntimeCall(
                                spec_version=spec_version,
                                module_id=module_id,
                                call_id=call.name,#call.get_identifier(),
                                index=idx,
                                name=call.name,
                                lookup='', #call.lookup,
                                documentation='\n'.join(call.docs),
                                count_params=len(call.args)
                            )
                            runtime_call.save(self.db_session)

                            for arg in call.args:
                                runtime_call_param = RuntimeCallParam(
                                    runtime_call_id=runtime_call.id,
                                    name=arg.name,
                                    type=arg.type
                                )
                                runtime_call_param.save(self.db_session)

                    if len(module.events or []) > 0:
                        for event_index, event in enumerate(module.events):
                            runtime_event = RuntimeEvent(
                                spec_version=spec_version,
                                module_id=module_id,
                                event_id=event.name,
                                index=event_index,
                                name=event.name,
                                lookup='', #event.lookup,
                                documentation='\n'.join(event.docs),
                                count_attributes=len(event.args)
                            )
                            runtime_event.save(self.db_session)

                            for arg_index, arg in enumerate(event.args):
                                # print(type(arg), arg)
                                runtime_event_attr = RuntimeEventAttribute(
                                    runtime_event_id=runtime_event.id,
                                    index=arg_index,
                                    type=arg.name
                                )
                                runtime_event_attr.save(self.db_session)

                    if len(storage_functions) > 0:
                        for idx, storage in enumerate(storage_functions):

                            # Determine type
                            type_hasher = None
                            type_key1 = None
                            type_key2 = None
                            type_value = None
                            type_is_linked = None
                            type_key2hasher = None

                            if storage.type.get('PlainType'):
                                type_value = storage.type.get('PlainType')

                            elif storage.type.get('MapType'):
                                type_hasher = storage.type['MapType'].get('hasher')
                                type_key1 = storage.type['MapType'].get('key')
                                type_value = storage.type['MapType'].get('value')
                                type_is_linked = storage.type['MapType'].get('isLinked', False)

                            elif storage.type.get('DoubleMapType'):
                                type_hasher = storage.type['DoubleMapType'].get('hasher')
                                type_key1 = storage.type['DoubleMapType'].get('key1')
                                type_key2 = storage.type['DoubleMapType'].get('key2')
                                type_value = storage.type['DoubleMapType'].get('value')
                                type_key2hasher = storage.type['DoubleMapType'].get('key2Hasher')

                            runtime_storage = RuntimeStorage(
                                spec_version=spec_version,
                                module_id=module_id,
                                index=idx,
                                name=storage.name,
                                lookup=None,
                                default='', #storage.default, #fallback
                                modifier=storage.modifier,
                                type_hasher=type_hasher,
                                storage_key=xxh128(storage.name.encode()), #xxh128(module.prefix.encode()) + 
                                type_key1=type_key1,
                                type_key2=type_key2,
                                type_value=type_value,
                                type_is_linked=type_is_linked,
                                type_key2hasher=type_key2hasher
                            )
                            runtime_storage.save(self.db_session)

                    if len(module.constants or []) > 0:
                        for idx, constant in enumerate(module.constants):

                            # Decode value
                            try:
                                value_obj = ScaleDecoder.get_decoder_class(
                                    constant.type,
                                    ScaleBytes(constant.constant_value)
                                )
                                value_obj.decode()
                                value = value_obj.serialize()
                            except ValueError:
                                value = constant.constant_value
                            except RemainingScaleBytesNotEmptyException:
                                value = constant.constant_value
                            except NotImplementedError:
                                value = constant.constant_value

                            if type(value) is list or type(value) is dict:
                                value = json.dumps(value)
                            if type(value) is bytearray:
                                value = value.hex()
                            runtime_constant = RuntimeConstant(
                                spec_version=spec_version,
                                module_id=module_id,
                                index=idx,
                                name=constant.name,
                                type=constant.type,
                                value=value
                            )
                            runtime_constant.save(self.db_session)

                    if len(module.errors or []) > 0:
                        for idx, error in enumerate(module.errors):
                            runtime_error = RuntimeErrorMessage(
                                spec_version=spec_version,
                                module_id=module_id,
                                module_index=module_index,
                                index=idx,
                                name=error.name
                            )
                            runtime_error.save(self.db_session)

                    runtime.save(self.db_session)

                # Process types
                for runtime_type_data in list(self.substrate.get_type_registry(block_hash=block_hash).values()):

                    runtime_type = RuntimeType(
                        spec_version=runtime_type_data["spec_version"],
                        type_string=runtime_type_data["type_string"],
                        decoder_class=runtime_type_data["decoder_class"],
                        is_primitive_core=runtime_type_data["is_primitive_core"],
                        is_primitive_runtime=runtime_type_data["is_primitive_runtime"]
                    )
                    runtime_type.save(self.db_session)

                self.db_session.commit()

                # Put in local store
                self.metadata_store[spec_version] = self.substrate.metadata_decoder
            except SQLAlchemyError as e:
                self.db_session.rollback()

    def add_block(self, block_hash):

        # Check if block is already process
        if Block.query(self.db_session).filter_by(hash=block_hash).count() > 0:
            raise BlockAlreadyAdded(block_hash)

        if settings.SUBSTRATE_MOCK_EXTRINSICS:
            self.substrate.mock_extrinsics = settings.SUBSTRATE_MOCK_EXTRINSICS

        json_block = self.substrate.get_chain_block(block_hash)

        parent_hash = json_block['block']['header'].pop('parentHash')
        block_id = json_block['block']['header'].pop('number')
        extrinsics_root = json_block['block']['header'].pop('extrinsicsRoot')
        state_root = json_block['block']['header'].pop('stateRoot')
        digest_logs = json_block['block']['header'].get('digest', {}).pop('logs', None)

        # Convert block number to numeric
        if not block_id.isnumeric():
            block_id = int(block_id, 16)

        # ==== Get block runtime from Substrate ==================

        self.substrate.init_runtime(block_hash=block_hash)

        self.process_metadata(self.substrate.runtime_version, block_hash)

        # ==== Get parent block runtime ===================

        if block_id > 0:
            json_parent_runtime_version = self.substrate.get_block_runtime_version(parent_hash)

            parent_spec_version = json_parent_runtime_version.get('specVersion', 0)

            self.process_metadata(parent_spec_version, parent_hash)
        else:
            parent_spec_version = self.substrate.runtime_version

        # ==== Set initial block properties =====================

        exist_block = Block.query(self.db_session).filter_by(
                id=block_id,
                parent_id=block_id - 1,
                hash=block_hash,
                parent_hash=parent_hash).first()

        if exist_block:
            block = exist_block
        else:
            block = Block(
                id=block_id,
                parent_id=block_id - 1,
                hash=block_hash,
                parent_hash=parent_hash,
                state_root=state_root,
                extrinsics_root=extrinsics_root,
                count_extrinsics=0,
                count_events=0,
                count_accounts_new=0,
                count_accounts_reaped=0,
                count_accounts=0,
                count_events_extrinsic=0,
                count_events_finalization=0,
                count_events_module=0,
                count_events_system=0,
                count_extrinsics_error=0,
                count_extrinsics_signed=0,
                count_extrinsics_signedby_address=0,
                count_extrinsics_signedby_index=0,
                count_extrinsics_success=0,
                count_extrinsics_unsigned=0,
                count_sessions_new=0,
                count_contracts_new=0,
                count_log=0,
                range10000=math.floor(block_id / 10000),
                range100000=math.floor(block_id / 100000),
                range1000000=math.floor(block_id / 1000000),
                spec_version_id=self.substrate.runtime_version,
                logs=digest_logs
            )

        # Set temp helper variables
        block._accounts_new = []
        block._accounts_reaped = []

        # ==== Get block events from Substrate ==================
        extrinsic_success_idx = {}
        events = []

        try:
            # TODO implemented solution in substrate interface for runtime transition blocks
            # Events are decoded against runtime of parent block
            RuntimeConfiguration().set_active_spec_version_id(parent_spec_version)
            events_decoder = self.substrate.get_events(block_hash)

            # Revert back to current runtime
            RuntimeConfiguration().set_active_spec_version_id(block.spec_version_id)

            event_idx = 0

            for event in events_decoder:

                event.value['module_id'] = event.value['module_id'].lower()

                model = Event.query(self.db_session).filter_by(block_id=block_id, event_idx=event_idx).first()
                if not model:
                    model = Event(
                        block_id=block_id,
                        event_idx=event_idx,
                        phase=0, #event.value['phase'],
                        extrinsic_idx=event.value['extrinsic_idx'],
                        type=event.value.get('event_index') or event.value.get('type'),
                        spec_version_id=parent_spec_version,
                        module_id=event.value['module_id'],
                        event_id=event.value['event_id'],
                        system=int(event.value['module_id'] == 'system'),
                        module=int(event.value['module_id'] != 'system'),
                        attributes=event.value['attributes'],
                        codec_error=False
                    )

                    # Process event

                    if event.value['phase'] == 0:
                        block.count_events_extrinsic += 1
                    elif event.value['phase'] == 1:
                        block.count_events_finalization += 1

                    if event.value['module_id'] == 'system':

                        block.count_events_system += 1

                        # Store result of extrinsic
                        if event.value['event_id'] == 'ExtrinsicSuccess':
                            extrinsic_success_idx[event.value['extrinsic_idx']] = True
                            block.count_extrinsics_success += 1

                        if event.value['event_id'] == 'ExtrinsicFailed':
                            extrinsic_success_idx[event.value['extrinsic_idx']] = False
                            block.count_extrinsics_error += 1
                    else:

                        block.count_events_module += 1

                    try:
                        model.save(self.db_session)
                    except IntegrityError:
                        self.db_session.rollback()

                events.append(model)

                event_idx += 1

            block.count_events = len(events_decoder)

        except SubstrateRequestException:
            block.count_events = 0
        #except ValueError:
        #    if block_id in [974059, 971763, 1022086, 1024652]:
        #        print("DEEPER--->>>  Event Parse Error!!!! {}".format(block_id))
        #        block.count_events = 0
        #    else:
        #        raise


        # === Extract extrinsics from block ====

        extrinsics_data = json_block['block'].pop('extrinsics')

        block.count_extrinsics = len(extrinsics_data)

        extrinsic_idx = 0

        extrinsics = []

        #if block_id == 891463:
        #    extrinsics_data = []


        for extrinsic in extrinsics_data:

            extrinsics_decoder = ExtrinsicsDecoder(
                data=ScaleBytes(extrinsic),
                metadata=self.metadata_store[parent_spec_version]
            )

            extrinsic_data = extrinsics_decoder.decode()

            # Lookup result of extrinsic
            extrinsic_success = extrinsic_success_idx.get(extrinsic_idx, False)

            # if extrinsics_decoder.era:
            #     era = extrinsics_decoder.era.raw_value
            # else:
            era = None
            if extrinsic_data.get('extrinsic_hash') is not None:
                extrinsic_hash = extrinsic_data.get('extrinsic_hash')[2:]
            else:
                extrinsic_hash = None

            module_id = ''
            call_id = ''
            params = ''
            if extrinsic_data.get('call') is not None:
                if extrinsic_data['call'].get('call_module') is not None:
                    module_id = extrinsic_data['call']['call_module']
                if extrinsic_data['call'].get('call_function') is not None:
                    call_id = extrinsic_data['call']['call_function']
                if extrinsic_data['call'].get('call_args') is not None:
                    params = extrinsic_data['call']['call_args']

            model = Extrinsic.query(self.db_session).filter_by(block_id=block_id, extrinsic_idx=extrinsic_idx).first()
            if not model:
                model = Extrinsic(
                    block_id=block_id,
                    extrinsic_idx=extrinsic_idx,
                    extrinsic_hash=extrinsic_hash,
                    extrinsic_length=extrinsic_data.get('extrinsic_length'),
                    extrinsic_version=extrinsic_data.get('version_info'),
                    signed=extrinsics_decoder.signed,
                    unsigned=not extrinsics_decoder.signed,
                    signedby_address=bool(extrinsic_data.get('extrinsic_hash') and extrinsic_data.get('account_id')),
                    signedby_index=bool(extrinsic_data.get('extrinsic_hash') and extrinsic_data.get('account_index')),
                    address_length=extrinsic_data.get('account_length'),
                    address=extrinsic_data.get('address', '').replace('0x', ''),
                    account_index=extrinsic_data.get('account_index'),
                    account_idx=extrinsic_data.get('account_idx'),
                    signature=extrinsic_data.get('signature', {}).get('Sr25519'),
                    nonce=extrinsic_data.get('nonce'),
                    era=era,
                    call=extrinsic_data.get('call_code'),
                    module_id=module_id,
                    call_id=call_id,
                    params=params,
                    spec_version_id=parent_spec_version,
                    success=int(extrinsic_success),
                    error=int(not extrinsic_success),
                    codec_error=False
                )
                try:
                    model.save(self.db_session)
                except IntegrityError:
                    self.db_session.rollback()

            extrinsics.append(model)

            extrinsic_idx += 1

            # Process extrinsic
            if extrinsics_decoder.signed:
                block.count_extrinsics_signed += 1

                if model.signedby_address:
                    block.count_extrinsics_signedby_address += 1
                if model.signedby_index:
                    block.count_extrinsics_signedby_index += 1

                # Add search index for signed extrinsics
                search_index = SearchIndex(
                    index_type_id=settings.SEARCH_INDEX_SIGNED_EXTRINSIC,
                    block_id=block.id,
                    extrinsic_idx=model.extrinsic_idx,
                    account_id=model.address
                )
                try:
                    search_index.save(self.db_session)
                except IntegrityError:
                    self.db_session.rollback()

            else:
                block.count_extrinsics_unsigned += 1

            # Process extrinsic processors
            for processor_class in ProcessorRegistry().get_extrinsic_processors(model.module_id, model.call_id):
                extrinsic_processor = processor_class(block, model, substrate=self.substrate)
                extrinsic_processor.accumulation_hook(self.db_session)
                extrinsic_processor.process_search_index(self.db_session)

        # Process event processors
        for event in events:
            extrinsic = None
            if event.extrinsic_idx is not None:
                try:
                    extrinsic = extrinsics[event.extrinsic_idx]
                except IndexError:
                    extrinsic = None

            for processor_class in ProcessorRegistry().get_event_processors(event.module_id, event.event_id):
                event_processor = processor_class(block, event, extrinsic,
                                                  metadata=self.metadata_store.get(block.spec_version_id),
                                                  substrate=self.substrate)
                event_processor.accumulation_hook(self.db_session)
                event_processor.process_search_index(self.db_session)

            event.block_datetime = block.datetime
            try:
                event.save(self.db_session)
            except IntegrityError:
                self.db_session.rollback()

        # Process block processors
        for processor_class in ProcessorRegistry().get_block_processors():
            block_processor = processor_class(block, substrate=self.substrate, harvester=self)
            block_processor.accumulation_hook(self.db_session)

        # Debug info
        if settings.DEBUG:
            block.debug_info = json_block

        # ==== Save data block ==================================
        if not exist_block:
            try:
                block.save(self.db_session)
            except IntegrityError:
                self.db_session.rollback()

        return block

    def remove_block(self, block_hash):
        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> remove_block")

        # Retrieve block
        block = Block.query(self.db_session).filter_by(hash=block_hash).first()

        # Revert event processors
        for event in Event.query(self.db_session).filter_by(block_id=block.id):
            for processor_class in ProcessorRegistry().get_event_processors(event.module_id, event.event_id):
                event_processor = processor_class(block, event, None)
                event_processor.accumulation_revert(self.db_session)

        # Revert extrinsic processors
        for extrinsic in Extrinsic.query(self.db_session).filter_by(block_id=block.id):
            for processor_class in ProcessorRegistry().get_extrinsic_processors(extrinsic.module_id, extrinsic.call_id):
                extrinsic_processor = processor_class(block, extrinsic)
                extrinsic_processor.accumulation_revert(self.db_session)

        # Revert block processors
        for processor_class in ProcessorRegistry().get_block_processors():
            block_processor = processor_class(block)
            block_processor.accumulation_revert(self.db_session)

        # Delete events
        for item in Event.query(self.db_session).filter_by(block_id=block.id):
            self.db_session.delete(item)
        # Delete extrinsics
        for item in Extrinsic.query(self.db_session).filter_by(block_id=block.id):
            self.db_session.delete(item)

        # Delete block
        self.db_session.delete(block)

    def sequence_block(self, block, parent_block_data=None, parent_sequenced_block_data=None):

        sequenced_block = BlockTotal(
            id=block.id
        )

        #if settings.DEEPER_DEBUG:
        #    print("DEEPER--->>> sequence_block block.id={}, parent_block_data={}, parent_sequenced_block_data={}".format(block.id, parent_block_data, parent_sequenced_block_data))

        # Process block processors
        for processor_class in ProcessorRegistry().get_block_processors():
            block_processor = processor_class(block, sequenced_block, substrate=self.substrate)
            block_processor.sequencing_hook(
                self.db_session,
                parent_block_data,
                parent_sequenced_block_data
            )

        extrinsics = Extrinsic.query(self.db_session).filter_by(block_id=block.id).order_by('extrinsic_idx')

        for extrinsic in extrinsics:
            # Process extrinsic processors
            for processor_class in ProcessorRegistry().get_extrinsic_processors(extrinsic.module_id, extrinsic.call_id):
                extrinsic_processor = processor_class(block, extrinsic, substrate=self.substrate)
                extrinsic_processor.sequencing_hook(
                    self.db_session,
                    parent_block_data,
                    parent_sequenced_block_data
                )

        events = Event.query(self.db_session).filter_by(block_id=block.id).order_by('event_idx')

        # Process event processors
        for event in events:
            extrinsic = None
            if event.extrinsic_idx is not None:
                try:
                    extrinsic = extrinsics[event.extrinsic_idx]
                except IndexError:
                    extrinsic = None

            for processor_class in ProcessorRegistry().get_event_processors(event.module_id, event.event_id):
                event_processor = processor_class(block, event, extrinsic, substrate=self.substrate)
                event_processor.sequencing_hook(
                    self.db_session,
                    parent_block_data,
                    parent_sequenced_block_data
                )

        sequenced_block.save(self.db_session)

        return sequenced_block

    def integrity_checks(self):

        # 1. Check finalized head
        substrate = SubstrateInterface(
            url=settings.SUBSTRATE_RPC_URL,
            runtime_config=RuntimeConfiguration(),
            type_registry_preset=settings.TYPE_REGISTRY
        )

        if settings.FINALIZATION_BY_BLOCK_CONFIRMATIONS > 0:
            finalized_block_hash = substrate.get_chain_head()
            finalized_block_number = max(
                substrate.get_block_number(finalized_block_hash) - settings.FINALIZATION_BY_BLOCK_CONFIRMATIONS, 0
            )
        else:
            finalized_block_hash = substrate.get_chain_finalised_head()
            finalized_block_number = substrate.get_block_number(finalized_block_hash)


        # 2. Check integrity head
        integrity_head = Status.get_status(self.db_session, 'INTEGRITY_HEAD')

        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> integrity_checks finalized_block_hash={}, finalized_block_number={}, integrity_head.value={}".format(finalized_block_hash,finalized_block_number,integrity_head.value))

        if not integrity_head.value:
            # Only continue if block #1 exists
            if Block.query(self.db_session).filter_by(id=1).count() == 0:
                if settings.DEEPER_DEBUG:
                    print('DEEPER--->>>  integrity_checks substrate.close 1')
                substrate.close()
                raise BlockIntegrityError('Chain not at genesis')

            integrity_head.value = 0
        else:
            integrity_head.value = int(integrity_head.value)

        start_block_id = max(integrity_head.value - 1, 0)
        end_block_id = min(finalized_block_number, start_block_id + 10000)
        chunk_size = 100
        parent_block = None
        integrity_head_hash = substrate.get_block_hash(integrity_head.value)

        if start_block_id < end_block_id:
            # Continue integrity check

            # print('== Start integrity checks from {} to {} =='.format(start_block_id, end_block_id))

            for block_nr in range(start_block_id, end_block_id, chunk_size):
                # TODO replace limit with filter_by block range
                block_range = Block.query(self.db_session).order_by('id')[block_nr:block_nr + chunk_size]
                for block in block_range:
                    if parent_block:
                        if block.id != parent_block.id + 1:

                            # Save integrity head if block hash of parent matches with hash in node
                            if parent_block.hash == integrity_head_hash:
                                integrity_head.save(self.db_session)
                                self.db_session.commit()

                            if settings.DEEPER_DEBUG:
                                print('DEEPER--->>>  integrity_checks substrate.close 2')
                            substrate.close()
                            # raise BlockIntegrityError('Block #{} is missing.. stopping check '.format(parent_block.id + 1))
                            print('Block #{} is missing.. stopping check and continue'.format(parent_block.id + 1))
                            BlockMissing.add_missing_range(self.db_session, parent_block.id + 1, block.id - 1)
                            return
                        elif block.parent_hash != parent_block.hash:

                            self.process_reorg_block(parent_block)
                            self.process_reorg_block(block)

                            self.remove_block(block.hash)
                            self.remove_block(parent_block.hash)
                            self.db_session.commit()

                            self.add_block(substrate.get_block_hash(block.id))
                            self.add_block(substrate.get_block_hash(parent_block.id))
                            self.db_session.commit()

                            integrity_head.value = parent_block.id - 1

                            # Save integrity head if block hash of parent matches with hash in node
                            #if parent_block.parent_hash == substrate.get_block_hash(integrity_head.value):
                            integrity_head.save(self.db_session)
                            self.db_session.commit()

                            if settings.DEEPER_DEBUG:
                                print('DEEPER--->>> integrity_checks substrate.close 3')
                            substrate.close()
                            # raise BlockIntegrityError('Block #{} failed integrity checks, Re-adding #{}.. '.format(parent_block.id, block.id))
                            print('Block #{} failed integrity checks, Re-adding #{}.. '.format(parent_block.id, block.id))
                            return
                        else:
                            integrity_head.value = block.id

                    parent_block = block
                    BlockMissing.fill_missing_range(self.db_session, block.id, block.id)
                    if block.id == end_block_id:
                        break

            if parent_block:
                # try:
                if parent_block.hash == integrity_head_hash:
                    integrity_head.save(self.db_session)
                    self.db_session.commit()
                # except BrokenPipeError:
                #     print('DEEPER--->>> integrity_checks substrate closed')
                #     substrate = SubstrateInterface(
                #         url=settings.SUBSTRATE_RPC_URL,
                #         runtime_config=RuntimeConfiguration(),
                #         type_registry_preset=settings.TYPE_REGISTRY
                #     )
                #     self.substrate.connect_websocket()

                #     if parent_block.hash == substrate.get_block_hash(int(integrity_head.value)):
                #         integrity_head.save(self.db_session)
                #         self.db_session.commit()

            if settings.DEEPER_DEBUG:
                print('DEEPER--->>> integrity_checks substrate.close 4')
            substrate.close()

        return {'integrity_head': integrity_head.value}

    def start_sequencer(self):
        self.integrity_checks()
        self.db_session.commit()

        block_nr = None

        integrity_head = Status.get_status(self.db_session, 'INTEGRITY_HEAD')

        if not integrity_head.value:
            integrity_head.value = 0

        # 3. Check sequence head
        sequencer_head = self.db_session.query(func.max(BlockTotal.id)).one()[0]

        if sequencer_head is None:
            sequencer_head = -1

        # Start sequencing process

        sequencer_parent_block = BlockTotal.query(self.db_session).filter_by(id=sequencer_head).first()
        parent_block = Block.query(self.db_session).filter_by(id=sequencer_head).first()

        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> start_sequencer sequencer_head={},  sequencer_parent_block={}, parent_block={}".format(sequencer_head, sequencer_parent_block, parent_block))

        for block_nr in range(sequencer_head + 1, int(integrity_head.value) + 1):

            if block_nr == 0:
                # No block ever sequenced, check if chain is at genesis state
                assert (not sequencer_parent_block)

                block = Block.query(self.db_session).order_by('id').first()

                if not block:
                    self.db_session.commit()
                    return {'error': 'Chain not at genesis'}

                if block.id == 1:
                    # Add genesis block
                    block = self.add_block(block.parent_hash)

                if block.id != 0:
                    self.db_session.commit()
                    return {'error': 'Chain not at genesis'}

                self.process_genesis(block)

                sequencer_parent_block_data = None
                parent_block_data = None
            else:
                block_id = sequencer_parent_block.id + 1

                assert (block_id == block_nr)

                block = Block.query(self.db_session).get(block_nr)

                if not block:
                    self.db_session.commit()
                    return {'result': 'Finished at #{}'.format(sequencer_parent_block.id)}

                sequencer_parent_block_data = sequencer_parent_block.asdict()
                parent_block_data = parent_block.asdict()

            sequenced_block = self.sequence_block(block, parent_block_data, sequencer_parent_block_data)
            self.db_session.commit()
            BlockMissing.fill_missing_range(self.db_session, block.id, block.id)
            parent_block = block
            sequencer_parent_block = sequenced_block

        if block_nr is None:
            return {'result': 'Finished at #{}'.format(block_nr)}
        else:
            return {'result': 'Nothing to sequence'}

    def process_reorg_block(self, block):
        # Check if reorg already exists
        if ReorgBlock.query(self.db_session).filter_by(hash=block.hash).count() == 0:

            model = ReorgBlock(**block.asdict())
            model.save(self.db_session)

            for extrinsic in Extrinsic.query(self.db_session).filter_by(block_id=block.id):
                model = ReorgExtrinsic(block_hash=block.hash, **extrinsic.asdict())
                model.save(self.db_session)

            for event in Event.query(self.db_session).filter_by(block_id=block.id):
                event_dict = event.asdict()
                if 'block_datetime' in event_dict:
                    del event_dict['block_datetime']
                model = ReorgEvent(block_hash=block.hash, **event_dict)
                model.save(self.db_session)

            for log in Log.query(self.db_session).filter_by(block_id=block.id):
                model = ReorgLog(block_hash=block.hash, **log.asdict())
                model.save(self.db_session)

    def rebuild_search_index(self, start, end):
        # if start and end:
        assert start <= end
        blocks = Block.query(self.db_session).order_by('id').yield_per(1000)
        blocks = blocks.filter(Block.id >= start, Block.id <= end)
        self.db_session.execute('DELETE FROM {} WHERE block_id >= {} AND block_id <= {}'.format(SearchIndex.__tablename__, start, end))
        # else:
        #     self.db_session.execute('truncate table {}'.format(SearchIndex.__tablename__))
        #     blocks = Block.query(self.db_session).order_by('id').yield_per(1000)

        for block in blocks:
            extrinsic_lookup = {}
            block._accounts_new = []
            block._accounts_reaped = []

            for extrinsic in Extrinsic.query(self.db_session).filter_by(block_id=block.id).order_by('extrinsic_idx'):
                extrinsic_lookup[extrinsic.extrinsic_idx] = extrinsic

                # Add search index for signed extrinsics
                if extrinsic.address:
                    search_index = SearchIndex(
                        index_type_id=settings.SEARCH_INDEX_SIGNED_EXTRINSIC,
                        block_id=block.id,
                        extrinsic_idx=extrinsic.extrinsic_idx,
                        account_id=extrinsic.address
                    )
                    search_index.save(self.db_session)

                # Process extrinsic processors
                for processor_class in ProcessorRegistry().get_extrinsic_processors(extrinsic.module_id, extrinsic.call_id):
                    extrinsic_processor = processor_class(block=block, extrinsic=extrinsic, substrate=self.substrate)
                    extrinsic_processor.process_search_index(self.db_session)

            for event in Event.query(self.db_session).filter_by(block_id=block.id).order_by('event_idx'):
                extrinsic = None
                if event.extrinsic_idx is not None:
                    try:
                        extrinsic = extrinsic_lookup[event.extrinsic_idx]
                    except (IndexError, KeyError):
                        extrinsic = None

                for processor_class in ProcessorRegistry().get_event_processors(event.module_id, event.event_id):
                    event_processor = processor_class(block, event, extrinsic,
                                                      metadata=self.metadata_store.get(block.spec_version_id),
                                                      substrate=self.substrate)
                    event_processor.process_search_index(self.db_session)

            self.db_session.commit()

    def create_full_balance_snaphot(self, block_id):
        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> create_full_balance_snaphot block_id={}".format(block_id))

        block_hash = self.substrate.get_block_hash(block_id)

        # Determine if keys have Blake2_128Concat format so AccountId is stored in storage key
        storage_method = self.substrate.get_metadata_storage_function(
            module_name="System",
            storage_name="Account",
            block_hash=block_hash
        )

        if storage_method:
            try:
                hasher = storage_method['type']['Map']['hasher']
            except:
                if 'hasher' in storage_method['type'].value['Map']:
                    hasher = storage_method['type'].value['Map']['hasher']
                else:
                    hasher = storage_method['type'].value['Map']['hashers'][0]

            if hasher == "Blake2_128Concat":

                # get balances storage prefix
                # storage_key_prefix = self.substrate.generate_storage_hash(
                #    storage_module='System',
                #    storage_function='Account'
                #)

                # rpc_result = self.substrate.rpc_request(
                #    'state_getKeys',
                #    [storage_key_prefix, block_hash]
                #).get('result')
                # Extract accounts from storage key
                #accounts = [storage_key[-64:] for storage_key in rpc_result if len(storage_key) == 162]

                # Retrieve accounts from database for legacy blocks
                accounts = [account[0] for account in self.db_session.query(distinct(Account.id))]
            else:
                # Retrieve accounts from database for legacy blocks
                accounts = [account[0] for account in self.db_session.query(distinct(Account.id))]

            for account_id in accounts:
                self.create_balance_snapshot(block_id=block_id, account_id=account_id, block_hash=block_hash)
                # self.db_session.commit()

    def create_balance_snapshot(self, block_id, account_id, block_hash=None, block_datetime=None):
        if not block_hash:
            block_hash = self.substrate.get_block_hash(block_id)

        if not block_datetime:
            # block = Block.query(self.db_session).filter_by(id=block_id).first()
            extrinsic = Extrinsic.query(self.db_session).filter_by(block_id=block_id, module_id='Timestamp', call_id='set').first()
            # print('create_balance_snapshot', extrinsic.params)
            for param in extrinsic.params:
                if param.get('name') == 'now':
                    try:
                        block_datetime = datetime.datetime.fromtimestamp(param.get('value')/1000)
                    except:
                        block_datetime = dateutil.parser.parse(param.get('value')).replace(tzinfo=pytz.UTC)

        # Get balance for account
        try:
            account_info_data = self.substrate.get_runtime_state(
                module='System',
                storage_function='Account',
                params=['0x{}'.format(account_id)],
                block_hash=block_hash
            ).get('result')

            # Make sure no rows inserted before processing this record
            AccountInfoSnapshot.query(self.db_session).filter_by(block_id=block_id, account_id=account_id).delete()

            if account_info_data:
                account_info_obj = AccountInfoSnapshot(
                    block_id=block_id,
                    block_datetime=block_datetime,
                    account_id=account_id,
                    account_info=account_info_data,
                    balance_free=account_info_data["data"]["free"],
                    balance_reserved=account_info_data["data"]["reserved"],
                    balance_total=account_info_data["data"]["free"] + account_info_data["data"]["reserved"],
                    nonce=account_info_data["nonce"]
                )
            else:
                account_info_obj = AccountInfoSnapshot(
                    block_id=block_id,
                    block_datetime=block_datetime,
                    account_id=account_id,
                    account_info=None,
                    balance_free=None,
                    balance_reserved=None,
                    balance_total=None,
                    nonce=None
                )

            account_info_obj.save(self.db_session)
        except ValueError:
            pass

    def update_account_balances(self):
        if settings.DEEPER_DEBUG:
            print("DEEPER--->>> update_account_balances")
        # set balances according to most recent snapshot
        account_info = self.db_session.execute("""
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
            Account.query(self.db_session).filter_by(id=account_id).update(
                {
                    Account.balance_total: balance_total,
                    Account.balance_free: balance_free,
                    Account.balance_reserved: balance_reserved,
                    Account.nonce: nonce,
                }, synchronize_session='fetch'
            )

    def deeper_test(self, block_hash):
        print("DEEPER--->>> deeper_test")
        substrate = SubstrateInterface(
            url='wss://mainnet-deeper-chain.deeper.network/',
            type_registry_preset='default',
            type_registry=load_type_registry_file('app/type_registry/custom_types.json'),
        )

        if block_hash:
            extrinsics = substrate.get_block(block_hash=block_hash)['extrinsics']
            print('Extrinsincs:', json.dumps([e.value for e in extrinsics], indent=4))
            events = substrate.get_events(block_hash)
            print("Events:", json.dumps([e.value for e in events], indent=4))


        account_info_data = substrate.get_runtime_state(
            module='System',
            storage_function='Account',
            params=['0x{}'.format("c83ad26723c4b2a7aa6c24b550186ab5a349ad87e37f71d897496914805cfc11")],
            block_hash='0xd626b0d19aae002015a508b1716dc63e7f4c8ea5aca5eb035c9bb714f7cc84cb' # err
            #block_hash='0xa20de815ad9e73e7b905598fce729584cf100a6c79c6fc390962364d60ecb3d1' # ok
        ).get('result')
        print("account_info_data: {}".format(account_info_data))


        print("DEEPER--->>> deeper_test finished")











