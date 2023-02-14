#  Polkascan PRE Explorer API
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
#  polkascan.py
from hashlib import blake2b
from datetime import datetime

import binascii
import json

import falcon
import pytz
from dogpile.cache.api import NO_VALUE
from scalecodec.type_registry import load_type_registry_preset
from sqlalchemy import func, tuple_, or_
from sqlalchemy.orm import defer, subqueryload, lazyload, lazyload_all

from app import settings
from app.models.data import Block, Extrinsic, Event, RuntimeCall, RuntimeEvent, Runtime, RuntimeModule, \
    RuntimeCallParam, RuntimeEventAttribute, RuntimeType, RuntimeStorage, Account, Session, Contract, \
    BlockTotal, SessionValidator, Log, AccountIndex, RuntimeConstant, SessionNominator, \
    RuntimeErrorMessage, SearchIndex, AccountInfoSnapshot
from app.resources.base import JSONAPIResource, JSONAPIListResource, JSONAPIDetailResource, BaseResource
from app.utils.ss58 import ss58_decode, ss58_encode
from scalecodec.base import RuntimeConfiguration
from substrateinterface import SubstrateInterface
import requests

class BlockDetailsResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'block_id'

    def get_item(self, item_id):
        if item_id.isnumeric():
            return Block.query(self.session).filter_by(id=item_id).first()
        else:
            return Block.query(self.session).filter_by(hash=item_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'extrinsics' in include_list:
            relationships['extrinsics'] = Extrinsic.query(self.session).filter_by(block_id=item.id).order_by(
                'extrinsic_idx')
        if 'transactions' in include_list:
            relationships['transactions'] = Extrinsic.query(self.session).options(defer('params')).filter_by(block_id=item.id, signed=1).order_by(
                'extrinsic_idx')
        if 'inherents' in include_list:
            relationships['inherents'] = Extrinsic.query(self.session).options(defer('params')).filter_by(block_id=item.id, signed=0).order_by(
                'extrinsic_idx')
        if 'events' in include_list:
            relationships['events'] = Event.query(self.session).filter_by(block_id=item.id).order_by(
                'event_idx')
        if 'logs' in include_list:
            relationships['logs'] = Log.query(self.session).filter_by(block_id=item.id).order_by(
                'log_idx')

        return relationships


class BlockListResource(JSONAPIListResource):

    def get_query(self):
        return Block.query(self.session).order_by(
            Block.id.desc()
        )


class BlockTotalDetailsResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        if item_id.isnumeric():
            return BlockTotal.query(self.session).get(item_id)
        else:
            block = Block.query(self.session).filter_by(hash=item_id).first()
            if block:
                return BlockTotal.query(self.session).get(block.id)

    def serialize_item(self, item):
        # Exclude large params from list view
        data = item.serialize()

        # Include author account
        if item.author_account:
            data['attributes']['author_account'] = item.author_account.serialize()
        return data

    def serialize_item(self, item):
        # Exclude large params from list view
        data = item.serialize()

        # Include author account
        if item.author_account:
            data['attributes']['author_account'] = item.author_account.serialize()
        return data


class BlockTotalListResource(JSONAPIListResource):

    def get_query(self):
        return BlockTotal.query(self.session).order_by(
            BlockTotal.id.desc()
        )

    def apply_filters(self, query, params):

        if params.get('filter[author]'):

            if len(params.get('filter[author]')) == 64:
                account_id = params.get('filter[author]')
            else:
                try:
                    account_id = ss58_decode(params.get('filter[author]'), settings.SUBSTRATE_ADDRESS_TYPE)
                except ValueError:
                    return query.filter(False)

            query = query.filter_by(author=account_id)

        return query


class ExtrinsicListResource(JSONAPIListResource):

    exclude_params = True

    def get_query(self):
        return Extrinsic.query(self.session).options(defer('params')).order_by(
            Extrinsic.block_id.desc()
        )

    def serialize_item(self, item):
        # Exclude large params from list view

        if self.exclude_params:
            data = item.serialize(exclude=['params'])
        else:
            data = item.serialize()

        # Add account as relationship
        if item.account:
            # data['relationships'] = {'account': {"type": "account", "id": item.account.id}}
            data['attributes']['account'] = item.account.serialize()
        return data

    # def get_included_items(self, items):
    #     # Include account items
    #     return [item.account.serialize() for item in items if item.account]

    def apply_filters(self, query, params):

        if params.get('filter[address]'):

            if len(params.get('filter[address]')) == 64:
                account_id = params.get('filter[address]')
            else:
                try:
                    account_id = ss58_decode(params.get('filter[address]'), settings.SUBSTRATE_ADDRESS_TYPE)
                except ValueError:
                    return query.filter(False)
        else:
            account_id = None

        if params.get('filter[search_index]'):

            self.exclude_params = False

            if type(params.get('filter[search_index]')) != list:
                params['filter[search_index]'] = [params.get('filter[search_index]')]

            search_index = SearchIndex.query(self.session).filter(
                SearchIndex.index_type_id.in_(params.get('filter[search_index]')),
                SearchIndex.account_id == account_id
            ).order_by(SearchIndex.sorting_value.desc())

            query = query.filter(tuple_(Extrinsic.block_id, Extrinsic.extrinsic_idx).in_(
                [[s.block_id, s.extrinsic_idx] for s in search_index]
            ))
        else:

            self.exclude_params = True

            if params.get('filter[signed]'):

                query = query.filter_by(signed=params.get('filter[signed]'))

            if params.get('filter[module_id]'):

                query = query.filter_by(module_id=params.get('filter[module_id]'))

            if params.get('filter[call_id]'):

                query = query.filter_by(call_id=params.get('filter[call_id]'))

            if params.get('filter[address]'):

                query = query.filter_by(address=account_id)

        return query


class ExtrinsicDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'extrinsic_id'

    def get_item(self, item_id):

        if item_id[0:2] == '0x':
            extrinsic = Extrinsic.query(self.session).filter_by(extrinsic_hash=item_id[2:]).first()
        else:

            if len(item_id.split('-')) != 2:
                return None

            extrinsic = Extrinsic.query(self.session).get(item_id.split('-'))

        return extrinsic

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'events' in include_list:
            relationships['events'] = Event.query(self.session).filter_by(
                block_id=item.block_id,
                extrinsic_idx=item.extrinsic_idx
            ).order_by('event_idx')

        return relationships

    def check_params(self, params, identifier):
        for idx, param in enumerate(params):

            if 'value' in param and 'type' in param:

                if type(param['value']) is list:
                    param['value'] = self.check_params(param['value'], identifier)

                else:
                    if param['type'] == 'Box<Call>':
                        param['value']['call_args'] = self.check_params(param['value']['call_args'], identifier)

                    elif type(param['value']) is str and len(param['value']) > 200000:
                        param['value'] = "{}/{}".format(
                            identifier,
                            blake2b(bytes.fromhex(param['value'].replace('0x', '')), digest_size=32).digest().hex()
                        )
                        param["type"] = "DownloadableBytesHash"
                        param['valueRaw'] = ""

        return params

    def serialize_item(self, item):
        data = item.serialize()

        runtime_call = RuntimeCall.query(self.session).filter_by(
            module_id=item.module_id,
            call_id=item.call_id,
            spec_version=item.spec_version_id
        ).first()

        data['attributes']['documentation'] = runtime_call.documentation

        block = Block.query(self.session).get(item.block_id)

        if block.datetime:
            data['attributes']['datetime'] = block.datetime.replace(tzinfo=pytz.UTC).isoformat()
        else:
            data['attributes']['datetime'] = None

        if item.account:
            data['attributes']['account'] = item.account.serialize()

        if item.params:
            item.params = self.check_params(item.params, item.serialize_id())

        if item.error:
            # Retrieve ExtrinsicFailed event
            extrinsic_failed_event = Event.query(self.session).filter_by(
                block_id=item.block_id,
                event_id='ExtrinsicFailed'
            ).first()

            # Retrieve runtime error
            if extrinsic_failed_event:
                if 'Module' in extrinsic_failed_event.attributes[0]:

                    error = RuntimeErrorMessage.query(self.session).filter_by(
                        module_index=extrinsic_failed_event.attributes[0]['Module']['index'],
                        index=extrinsic_failed_event.attributes[0]['Module']['error'],
                        spec_version=item.spec_version_id
                    ).first()

                    if error:
                        data['attributes']['error_message'] = error.documentation
                elif 'BadOrigin' in extrinsic_failed_event.attributes[0]:
                    data['attributes']['error_message'] = 'Bad origin'
                elif 'CannotLookup' in extrinsic_failed_event.attributes[0]:
                    data['attributes']['error_message'] = 'Cannot lookup'

        return data


class EventsListResource(JSONAPIListResource):

    def apply_filters(self, query, params):

        if params.get('filter[address]'):

            if len(params.get('filter[address]')) == 64:
                account_id = params.get('filter[address]')
            else:
                try:
                    account_id = ss58_decode(params.get('filter[address]'), settings.SUBSTRATE_ADDRESS_TYPE)
                except ValueError:
                    return query.filter(False)
        else:
            account_id = None

        if params.get('filter[search_index]'):

            if type(params.get('filter[search_index]')) != list:
                params['filter[search_index]'] = [params.get('filter[search_index]')]

            search_index = SearchIndex.query(self.session).filter(
                SearchIndex.index_type_id.in_(params.get('filter[search_index]')),
                SearchIndex.account_id == account_id
            ).order_by(SearchIndex.sorting_value.desc())

            query = query.filter(tuple_(Event.block_id, Event.event_idx).in_(
                [[s.block_id, s.event_idx] for s in search_index]
            ))
        else:

            if params.get('filter[module_id]'):
                query = query.filter_by(module_id=params.get('filter[module_id]'))

            if params.get('filter[event_id]'):

                query = query.filter_by(event_id=params.get('filter[event_id]'))
            else:
                query = query.filter(Event.event_id.notin_(['ExtrinsicSuccess', 'ExtrinsicFailed']))

        return query

    def get_query(self):
        return Event.query(self.session).order_by(
            Event.block_id.desc()
        )


class EventDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'event_id'

    def get_item(self, item_id):
        if len(item_id.split('-')) != 2:
            return None
        return Event.query(self.session).get(item_id.split('-'))

    def serialize_item(self, item):
        data = item.serialize()
        if 'attributes' in data and 'attributes' in data['attributes'] and not isinstance(data['attributes']['attributes'], list) and not isinstance(data['attributes']['attributes'], dict):
            data['attributes']['attributes'] = [data['attributes']['attributes']]
        for idx, attr in enumerate(data['attributes']['attributes']):
            if type(attr) == str and len(attr) == 66 and attr.startswith('0x'):
                data['attributes']['attributes'][idx] = ss58_encode(attr.replace('0x', ''), settings.SUBSTRATE_ADDRESS_TYPE)

        runtime_event = RuntimeEvent.query(self.session).filter_by(
            module_id=item.module_id,
            event_id=item.event_id,
            spec_version=item.spec_version_id
        ).first()

        data['attributes']['documentation'] = runtime_event.documentation

        return data


class LogListResource(JSONAPIListResource):

    def get_query(self):
        return Log.query(self.session).order_by(
            Log.block_id.desc()
        )


class LogDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        if len(item_id.split('-')) != 2:
            return None
        return Log.query(self.session).get(item_id.split('-'))


class NetworkStatisticsResource(JSONAPIResource):

    cache_expiration_time = 6

    def on_get(self, req, resp, network_id=None):
        resp.status = falcon.HTTP_200

        # TODO make caching more generic for custom resources

        cache_key = '{}-{}'.format(req.method, req.url)

        response = self.cache_region.get(cache_key, self.cache_expiration_time)

        if response is NO_VALUE:

            best_block = BlockTotal.query(self.session).filter_by(id=self.session.query(func.max(BlockTotal.id)).one()[0]).first()

            # print('XXX--->>>', best_block.id)
            # print('XXX--->>>', int(best_block.total_extrinsics_signed))
            # print('XXX--->>> cache_key ', cache_key)
            # print('XXX--->>> self.session ', self.session)
            # print('XXX--->>> BlockTotal ' , BlockTotal)
            # print('XXX--->>> BlockTotal.query ' , BlockTotal.query)


            if best_block:
                response = self.get_jsonapi_response(
                    data={
                        'type': 'networkstats',
                        'id': network_id,
                        'attributes': {
                            'best_block': best_block.id,
                            'total_signed_extrinsics': int(best_block.total_extrinsics_signed),
                            'total_events': int(best_block.total_events),
                            'total_events_module': int(best_block.total_events_module),
                            'total_blocks': 'N/A',
                            'total_accounts': int(best_block.total_accounts),
                            'total_runtimes': Runtime.query(self.session).count()
                        }
                    },
                )
            else:
                response = self.get_jsonapi_response(
                    data={
                        'type': 'networkstats',
                        'id': network_id,
                        'attributes': {
                            'best_block': 0,
                            'total_signed_extrinsics': 0,
                            'total_events': 0,
                            'total_events_module': 0,
                            'total_blocks': 'N/A',
                            'total_accounts': 0,
                            'total_runtimes': 0
                        }
                    },
                )
            self.cache_region.set(cache_key, response)
            resp.set_header('X-Cache', 'MISS')
        else:
            resp.set_header('X-Cache', 'HIT')

        resp.media = response


class BalanceTransferListResource(JSONAPIListResource):

    def get_query(self):
        return Event.query(self.session).filter(
            Event.module_id == 'balances', Event.event_id == 'Transfer'
        ).order_by(Event.block_id.desc())

    def apply_filters(self, query, params):
        if params.get('filter[address]'):

            if len(params.get('filter[address]')) == 64:
                account_id = params.get('filter[address]')
            else:
                try:
                    account_id = ss58_decode(params.get('filter[address]'), settings.SUBSTRATE_ADDRESS_TYPE)
                except ValueError:
                    return query.filter(False)

            search_index = SearchIndex.query(self.session).filter(
                SearchIndex.index_type_id.in_([
                    # settings.SEARCH_INDEX_CLAIMS_CLAIMED,
                    # settings.SEARCH_INDEX_STAKING_REWARD,
                    settings.SEARCH_INDEX_BALANCES_DEPOSIT,
                    settings.SEARCH_INDEX_BALANCETRANSFER
                ]),
                SearchIndex.account_id == account_id
            ).order_by(SearchIndex.block_id.desc()).limit(1000) # to avoid too many results

            query = Event.query(self.session).filter(tuple_(Event.block_id, Event.event_idx).in_(
                [[s.block_id, s.event_idx] for s in search_index]
            )).order_by(Event.block_id.desc())


        return query

    def serialize_item(self, item):
        if item.event_id == 'Transfer':
            sender_id = 'unknown'
            if type(item.attributes[0]) == str:
                sender_id = item.attributes[0].replace('0x', '')
            elif item.attributes[0] and 'value' in item.attributes[0] and type(item.attributes[0]['value']) == str:
                sender_id = item.attributes[0]['value'].replace('0x', '')
            sender = Account.query(self.session).get(sender_id)
            if sender:
                sender_data = sender.serialize()
            else:
                sender_data = {
                    'type': 'account',
                    'id': sender_id,
                    'attributes': {
                        'id': sender_id,
                        'address': ss58_encode(sender_id, settings.SUBSTRATE_ADDRESS_TYPE)
                    }
                }

            destination_id = 'unknown'
            if type(item.attributes[1]) == str:
                destination_id = item.attributes[1].replace('0x', '')
            elif item.attributes[1] and 'value' in item.attributes[1] and type(item.attributes[1]['value']) == str:
                destination_id = item.attributes[1]['value'].replace('0x', '')
            destination = Account.query(self.session).get(destination_id)
            if destination:
                destination_data = destination.serialize()
            else:
                destination_data = {
                    'type': 'account',
                    'id': destination_id,
                    'attributes': {
                        'id': destination_id,
                        'address': ss58_encode(destination_id, settings.SUBSTRATE_ADDRESS_TYPE)
                    }
                }

            # Some networks don't have fees
            if len(item.attributes) == 4:
                fee = item.attributes[3]
            else:
                fee = 0

            try:
                value = item.attributes[2]['value']
            except:
                value = item.attributes[2]

        elif item.event_id == 'Deposit':

            fee = 0
            sender_data = {'name': 'Deposit'}
            destination_data = {}
            value = 0
            if type(item.attributes[1]) == int or type(item.attributes[1]) == float or type(item.attributes[1]) == str:
                value = item.attributes[1]
            elif item.attributes[1] and 'value' in item.attributes[1]:
                value = item.attributes[1]['value']

        else:
            sender_data = {}
            fee = 0
            destination_data = {}
            value = None

        return {
            'type': 'balancetransfer',
            'id': '{}-{}'.format(item.block_id, item.event_idx),
            'attributes': {
                'block_id': item.block_id,
                'event_id': item.event_id,
                'event_idx': '{}-{}'.format(item.block_id, item.event_idx),
                'sender': sender_data,
                'destination': destination_data,
                'value': value,
                'fee': fee
            }
        }


class BalanceTransferDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Event.query(self.session).get(item_id.split('-'))

    def serialize_item(self, item):

        sender = Account.query(self.session).get(item.attributes[0]['value'].replace('0x', ''))

        if sender:
            sender_data = sender.serialize()
        else:
            sender_data = {
                'type': 'account',
                'id': item.attributes[0]['value'].replace('0x', ''),
                'attributes': {
                    'id': item.attributes[0]['value'].replace('0x', ''),
                    'address': ss58_encode(item.attributes[0]['value'].replace('0x', ''), settings.SUBSTRATE_ADDRESS_TYPE)
                }
            }

        destination = Account.query(self.session).get(item.attributes[1]['value'].replace('0x', ''))

        if destination:
            destination_data = destination.serialize()
        else:
            destination_data = {
                'type': 'account',
                'id': item.attributes[1]['value'].replace('0x', ''),
                'attributes': {
                    'id': item.attributes[1]['value'].replace('0x', ''),
                    'address': ss58_encode(item.attributes[1]['value'].replace('0x', ''), settings.SUBSTRATE_ADDRESS_TYPE)
                }
            }

        # Some networks don't have fees
        if len(item.attributes) == 4:
            fee = item.attributes[3]['value']
        else:
            fee = 0

        return {
            'type': 'balancetransfer',
            'id': '{}-{}'.format(item.block_id, item.event_idx),
            'attributes': {
                'block_id': item.block_id,
                'event_idx': '{}-{}'.format(item.block_id, item.event_idx),
                'sender': sender_data,
                'destination': destination_data,
                'value': item.attributes[2]['value'],
                'fee': fee
            }
        }


class AccountResource(JSONAPIListResource):

    def get_query(self):
        return Account.query(self.session).order_by(
            Account.balance_total.desc()
        )

    def apply_filters(self, query, params):

        if params.get('filter[is_validator]'):
            query = query.filter_by(is_validator=True)

        if params.get('filter[is_nominator]'):
            query = query.filter_by(is_nominator=True)

        if params.get('filter[is_council_member]'):
            query = query.filter_by(is_council_member=True)

        if params.get('filter[is_registrar]'):
            query = query.filter_by(is_registrar=True)

        if params.get('filter[is_sudo]'):
            query = query.filter_by(is_sudo=True)

        if params.get('filter[is_tech_comm_member]'):
            query = query.filter_by(is_tech_comm_member=True)

        if params.get('filter[is_treasury]'):
            query = query.filter_by(is_treasury=True)

        if params.get('filter[was_validator]'):
            query = query.filter_by(was_validator=True)

        if params.get('filter[was_nominator]'):
            query = query.filter_by(was_nominator=True)

        if params.get('filter[was_council_member]'):
            query = query.filter_by(was_council_member=True)

        if params.get('filter[was_registrar]'):
            query = query.filter_by(was_registrar=True)

        if params.get('filter[was_sudo]'):
            query = query.filter_by(was_sudo=True)

        if params.get('filter[was_tech_comm_member]'):
            query = query.filter_by(was_tech_comm_member=True)

        if params.get('filter[has_identity]'):
            query = query.filter_by(has_identity=True, identity_judgement_bad=0)

        if params.get('filter[has_subidentity]'):
            query = query.filter_by(has_subidentity=True, identity_judgement_bad=0)

        if params.get('filter[identity_judgement_good]'):
            query = query.filter(Account.identity_judgement_good > 0, Account.identity_judgement_bad == 0)

        if params.get('filter[blacklist]'):
            query = query.filter(Account.identity_judgement_bad > 0)

        return query


class AccountDetailResource(JSONAPIDetailResource):

    cache_expiration_time = 12

    def __init__(self):
        RuntimeConfiguration().update_type_registry(load_type_registry_preset(name="core"))
        if settings.TYPE_REGISTRY != 'core':
            RuntimeConfiguration().update_type_registry(load_type_registry_preset(settings.TYPE_REGISTRY))
        super(AccountDetailResource, self).__init__()

    def get_item(self, item_id):
        return Account.query(self.session).filter(or_(Account.address == item_id, Account.index_address == item_id)).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                address=item.id).order_by(Extrinsic.block_id.desc())[:10]

        if 'indices' in include_list:
            relationships['indices'] = AccountIndex.query(self.session).filter_by(
                account_id=item.id).order_by(AccountIndex.updated_at_block.desc())

        return relationships

    def serialize_item(self, item):
        data = item.serialize()

        # Get balance history
        account_info_snapshot = AccountInfoSnapshot.query(self.session).filter_by(
                account_id=item.id
        ).order_by(AccountInfoSnapshot.block_id.desc())[:1000]

        data['attributes']['balance_history'] = [
            {
                'name': "Total balance",
                'type': 'line',
                'data': [
                    [item.block_id, float((item.balance_total or 0) / 10**settings.SUBSTRATE_TOKEN_DECIMALS), item.block_datetime.strftime("%Y/%m/%d %H:%M:%S")]
                    for item in reversed(account_info_snapshot)
                ],
            }
        ]

        if settings.USE_NODE_RETRIEVE_BALANCES == 'True':

            substrate = SubstrateInterface(
                url=settings.SUBSTRATE_RPC_URL,
                type_registry_preset=settings.TYPE_REGISTRY
            )

            if settings.SUBSTRATE_STORAGE_BALANCE == 'Account':
                storage_call = RuntimeStorage.query(self.session).filter_by(
                    module_id='system',
                    name='Account',
                ).order_by(RuntimeStorage.spec_version.desc()).first()

                if storage_call:
                    account_data = substrate.query(
                        block_hash=None,
                        module='System',
                        storage_function='Account',
                        params=[item.id],
                        # return_scale_type=storage_call.type_value,
                        # hasher=storage_call.type_hasher,
                        # metadata_version=settings.SUBSTRATE_METADATA_VERSION
                    )

                    if account_data:
                        data['attributes']['free_balance'] = account_data['data']['free']
                        data['attributes']['reserved_balance'] = account_data['data']['reserved']
                        data['attributes']['misc_frozen_balance'] = account_data['data']['miscFrozen']
                        data['attributes']['fee_frozen_balance'] = account_data['data']['feeFrozen']
                        data['attributes']['nonce'] = account_data['nonce']

            elif settings.SUBSTRATE_STORAGE_BALANCE == 'Balances.Account':

                storage_call = RuntimeStorage.query(self.session).filter_by(
                    module_id='balances',
                    name='Account',
                ).order_by(RuntimeStorage.spec_version.desc()).first()

                if storage_call:
                    account_data = substrate.query(
                        block_hash=None,
                        module='Balances',
                        storage_function='Account',
                        params=[item.id],
                        # return_scale_type=storage_call.type_value,
                        # hasher=storage_call.type_hasher,
                        # metadata_version=settings.SUBSTRATE_METADATA_VERSION
                    )

                    if account_data:
                        data['attributes']['balance_free'] = account_data['free']
                        data['attributes']['balance_reserved'] = account_data['reserved']
                        data['attributes']['misc_frozen_balance'] = account_data['miscFrozen']
                        data['attributes']['fee_frozen_balance'] = account_data['feeFrozen']
                        data['attributes']['nonce'] = None
            else:

                storage_call = RuntimeStorage.query(self.session).filter_by(
                    module_id='balances',
                    name='FreeBalance',
                ).order_by(RuntimeStorage.spec_version.desc()).first()

                if storage_call:
                    data['attributes']['free_balance'] = substrate.query(
                        block_hash=None,
                        module='Balances',
                        storage_function='FreeBalance',
                        params=[item.id],
                        # return_scale_type=storage_call.type_value,
                        # hasher=storage_call.type_hasher,
                        # metadata_version=settings.SUBSTRATE_METADATA_VERSION
                    )

                storage_call = RuntimeStorage.query(self.session).filter_by(
                    module_id='balances',
                    name='ReservedBalance',
                ).order_by(RuntimeStorage.spec_version.desc()).first()

                if storage_call:
                    data['attributes']['reserved_balance'] = substrate.query(
                        block_hash=None,
                        module='Balances',
                        storage_function='ReservedBalance',
                        params=[item.id],
                        # return_scale_type=storage_call.type_value,
                        # hasher=storage_call.type_hasher,
                        # metadata_version=settings.SUBSTRATE_METADATA_VERSION
                    )

                storage_call = RuntimeStorage.query(self.session).filter_by(
                    module_id='system',
                    name='AccountNonce',
                ).order_by(RuntimeStorage.spec_version.desc()).first()

                if storage_call:

                    data['attributes']['nonce'] = substrate.query(
                        block_hash=None,
                        module='System',
                        storage_function='AccountNonce',
                        params=[item.id],
                        # return_scale_type=storage_call.type_value,
                        # hasher=storage_call.type_hasher,
                        # metadata_version=settings.SUBSTRATE_METADATA_VERSION
                    )

        return data


class AccountIndexListResource(JSONAPIListResource):

    def get_query(self):
        return AccountIndex.query(self.session).order_by(
            AccountIndex.updated_at_block.desc()
        )


class AccountIndexDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return AccountIndex.query(self.session).filter_by(short_address=item_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                address=item.account_id).order_by(Extrinsic.block_id.desc())[:10]

        return relationships

    def serialize_item(self, item):
        data = item.serialize()

        if item.account:
            data['attributes']['account'] = item.account.serialize()

        return data


class SessionListResource(JSONAPIListResource):

    cache_expiration_time = 60

    def get_query(self):
        return Session.query(self.session).order_by(
            Session.id.desc()
        )


class SessionDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Session.query(self.session).get(item_id)

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'blocks' in include_list:
            relationships['blocks'] = Block.query(self.session).filter_by(
                session_id=item.id
            ).order_by(Block.id.desc())

        if 'validators' in include_list:
            relationships['validators'] = SessionValidator.query(self.session).filter_by(
                session_id=item.id
            ).order_by(SessionValidator.rank_validator)

        return relationships


class SessionValidatorListResource(JSONAPIListResource):

    cache_expiration_time = 60

    def get_query(self):
        return SessionValidator.query(self.session).order_by(
            SessionValidator.session_id, SessionValidator.rank_validator
        )

    def apply_filters(self, query, params):

        if params.get('filter[latestSession]'):

            session = Session.query(self.session).order_by(Session.id.desc()).first()

            query = query.filter_by(session_id=session.id)

        return query


class SessionValidatorDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):

        if len(item_id.split('-')) != 2:
            return None

        session_id, rank_validator = item_id.split('-')
        return SessionValidator.query(self.session).filter_by(
            session_id=session_id,
            rank_validator=rank_validator
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'nominators' in include_list:
            relationships['nominators'] = SessionNominator.query(self.session).filter_by(
                session_id=item.session_id, rank_validator=item.rank_validator
            ).order_by(SessionNominator.rank_nominator)

        return relationships

    def serialize_item(self, item):
        data = item.serialize()

        if item.validator_stash_account:
            data['attributes']['validator_stash_account'] = item.validator_stash_account.serialize()

        if item.validator_controller_account:
            data['attributes']['validator_controller_account'] = item.validator_controller_account.serialize()

        return data


class SessionNominatorListResource(JSONAPIListResource):

    cache_expiration_time = 60

    def get_query(self):
        return SessionNominator.query(self.session).order_by(
            SessionNominator.session_id, SessionNominator.rank_validator, SessionNominator.rank_nominator
        )

    def apply_filters(self, query, params):

        if params.get('filter[latestSession]'):

            session = Session.query(self.session).order_by(Session.id.desc()).first()

            query = query.filter_by(session_id=session.id)

        return query


class ContractListResource(JSONAPIListResource):

    def get_query(self):
        return Contract.query(self.session).order_by(
            Contract.created_at_block.desc()
        )


class ContractDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Contract.query(self.session).get(item_id)


class RuntimeListResource(JSONAPIListResource):

    cache_expiration_time = 60

    def get_query(self):
        return Runtime.query(self.session).order_by(
            Runtime.id.desc()
        )


class RuntimeDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Runtime.query(self.session).get(item_id)

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'modules' in include_list:
            relationships['modules'] = RuntimeModule.query(self.session).filter_by(
                spec_version=item.spec_version
            ).order_by('lookup', 'id')

        if 'types' in include_list:
            relationships['types'] = RuntimeType.query(self.session).filter_by(
                spec_version=item.spec_version
            ).order_by('type_string')

        return relationships


class RuntimeCallListResource(JSONAPIListResource):

    cache_expiration_time = 3600

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):

            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        if params.get('filter[module_id]'):

            query = query.filter_by(module_id=params.get('filter[module_id]'))

        return query

    def get_query(self):
        return RuntimeCall.query(self.session).order_by(
            RuntimeCall.spec_version.asc(), RuntimeCall.module_id.asc(), RuntimeCall.call_id.asc()
        )


class RuntimeCallDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'runtime_call_id'

    def get_item(self, item_id):

        if len(item_id.split('-')) != 3:
            return None

        spec_version, module_id, call_id = item_id.split('-')
        return RuntimeCall.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            call_id=call_id
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'params' in include_list:
            relationships['params'] = RuntimeCallParam.query(self.session).filter_by(
                runtime_call_id=item.id).order_by('id')

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                call_id=item.call_id, module_id=item.module_id).order_by(Extrinsic.block_id.desc())[:10]

        return relationships


class RuntimeEventListResource(JSONAPIListResource):

    cache_expiration_time = 3600

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):

            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        if params.get('filter[module_id]'):

            query = query.filter_by(module_id=params.get('filter[module_id]'))

        return query

    def get_query(self):
        return RuntimeEvent.query(self.session).order_by(
            RuntimeEvent.spec_version.asc(), RuntimeEvent.module_id.asc(), RuntimeEvent.event_id.asc()
        )


class RuntimeEventDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'runtime_event_id'

    def get_item(self, item_id):

        if len(item_id.split('-')) != 3:
            return None

        spec_version, module_id, event_id = item_id.split('-')
        return RuntimeEvent.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            event_id=event_id
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'attributes' in include_list:
            relationships['attributes'] = RuntimeEventAttribute.query(self.session).filter_by(
                runtime_event_id=item.id).order_by('id')

        if 'recent_events' in include_list:
            relationships['recent_events'] = Event.query(self.session).filter_by(
                event_id=item.event_id, module_id=item.module_id).order_by(Event.block_id.desc())[:10]

        return relationships


class RuntimeTypeListResource(JSONAPIListResource):

    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeType.query(self.session).order_by(
            'spec_version', 'type_string'
        )

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):

            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        return query


class RuntimeModuleListResource(JSONAPIListResource):

    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeModule.query(self.session).order_by(
            'spec_version', 'name'
        )

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):

            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        return query


class RuntimeModuleDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):

        if len(item_id.split('-')) != 2:
            return None

        spec_version, module_id = item_id.split('-')
        return RuntimeModule.query(self.session).filter_by(spec_version=spec_version, module_id=module_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'calls' in include_list:
            relationships['calls'] = RuntimeCall.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'lookup', 'id')

        if 'events' in include_list:
            relationships['events'] = RuntimeEvent.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'lookup', 'id')

        if 'storage' in include_list:
            relationships['storage'] = RuntimeStorage.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'name')

        if 'constants' in include_list:
            relationships['constants'] = RuntimeConstant.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'name')

        if 'errors' in include_list:
            relationships['errors'] = RuntimeErrorMessage.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'name').order_by(RuntimeErrorMessage.index)

        return relationships


class RuntimeStorageDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):

        if len(item_id.split('-')) != 3:
            return None

        spec_version, module_id, name = item_id.split('-')
        return RuntimeStorage.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            name=name
        ).first()


class RuntimeConstantListResource(JSONAPIListResource):

    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeConstant.query(self.session).order_by(
            RuntimeConstant.spec_version.desc(), RuntimeConstant.module_id.asc(), RuntimeConstant.name.asc()
        )


class RuntimeConstantDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):

        if len(item_id.split('-')) != 3:
            return None

        spec_version, module_id, name = item_id.split('-')
        return RuntimeConstant.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            name=name
        ).first()


'''
const config = require('../config/config');
const logger = require('../../common-js/log');
const walletUtil = require('../libs/wallet');
const processArg = require('./processArg');
const chainDb = require('../libs/chainDb');
const LIST_QUERY =
  'SELECT block_id, event_idx, module_id, event_id, _from, _to, amount, timestamp FROM transaction WHERE';
const SUM_QUERY = 'SELECT SUM(amount) AS sum FROM transaction WHERE';
const TYPE_CONDITION = 'AND (module_id = ? AND event_id = ?)';
const START_TIME_CONDITION = 'AND timestamp >= ?';
const END_TIME_CONDITION = 'AND timestamp < ?';
const AMOUNT_CONVERSION_RATE = config.AMOUNT_CONVERSION_RATE;
const SYSTEM_WALLET_ACCOUNT = '000000000000000000000000000000000000000000000000';
const accountMap = {};
exports.validPositions = ['from', 'to'];
exports.validTxnTypes = ['balances.Transfer', 'staking.DelegatorReward', 'micropayment.ClaimPayment'];
exports.list = async (publicKey, position, type, start, end) => {
  const rows = await query(LIST_QUERY, publicKey, position, type, start, end);
  if (!rows) {
    return [];
  }
  return processRows(rows);
};
async function query(baseQuery, publicKey, position, type, start, end) {
  const hex = addressToHex(publicKey);
  if (!hex) {
    logger.error(
      `Failed to query ${processArg.isTestnetMode() ? 'Testnet' : 'Mainnet'}: unable to convert ${publicKey} to hex`
    );
    return null;
  }
  let query = baseQuery;
  const params = [hex];
  if (position && exports.validPositions.includes(position)) {
    query = `${query} _${position} = ?`;
  } else {
    query = `${query} (_from = ? OR _to = ?)`;
    params.push(hex);
  }
  if (type && exports.validTxnTypes.includes(type)) {
    query = `${query} ${TYPE_CONDITION}`;
    const typeArr = type.split('.');
    params.push(typeArr[0]);
    params.push(typeArr[1]);
  }
  if (start) {
    query = `${query} ${START_TIME_CONDITION}`;
    params.push(start / 1000);
  }
  if (end) {
    query = `${query} ${END_TIME_CONDITION}`;
    params.push(end / 1000);
  }
  const rows = await chainDb.query(query, params);
  return rows;
}
function addressToHex(address) {
  return convertAccount(address, walletUtil.addressToHex);
}
function hexToAddress(hex) {
  return convertAccount(hex, walletUtil.hexToAddress);
}
function convertAccount(src, convertFunc) {
  if (accountMap[src]) {
    return accountMap[src];
  }
  const dst = convertFunc(src);
  if (dst) {
    accountMap[src] = dst;
    accountMap[dst] = src;
  }
  return dst;
}
function processRows(rows) {
  return rows.map(row => {
    const amount = (row.amount * AMOUNT_CONVERSION_RATE).toFixed(config.FUND_PRECISION);
    const timestamp = row.timestamp * 1000;
    return {
      id: `${row.block_id}-${row.event_idx}`,
      type: `${row.module_id}.${row.event_id}`,
      from: row._from ? hexToAddress(row._from) : SYSTEM_WALLET_ACCOUNT,
      to: hexToAddress(row._to),
      amount: amount,
      timestamp: timestamp,
    };
  });
}
exports.sum = async (publicKey, position, type, start, end) => {
  const rows = await query(SUM_QUERY, publicKey, position, type, start, end);
  const sum = (rows && rows[0] && rows[0].sum) || 0;
  return (sum * AMOUNT_CONVERSION_RATE).toFixed(config.FUND_PRECISION);
};
'''

class TransactionResource(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr', None)
        from_addr = req.get_param('from', None)
        to_addr = req.get_param('to', None)
        sum = str(req.get_param('sum')).lower() == 'true'

        if sum:
            sql = 'SELECT SUM(amount) AS sum FROM transaction WHERE'
        else:
            sql = 'SELECT block_id, event_idx, module_id, event_id, _from, _to, amount, timestamp FROM transaction WHERE'
        params = {}
        if addr:
            assert ' ' not in addr
            range_condition = ' (_from=:from OR _to=:to)'
            if addr.startswith('0x'):
                params['from'] = addr
                params['to'] = addr
            else:
                params['from'] = '0x'+ss58_decode(addr)
                params['to'] = '0x'+ss58_decode(addr)

        elif from_addr:
            assert ' ' not in from_addr
            range_condition = ' _from=:from'
            if from_addr.startswith('0x'):
                params['from'] = from_addr
            else:
                params['from'] = '0x'+ss58_decode(from_addr)

        elif to_addr:
            assert ' ' not in to_addr
            range_condition = ' _to=:to'
            if to_addr.startswith('0x'):
                params['to'] = to_addr
            else:
                params['to'] = '0x'+ss58_decode(to_addr)
        else:
            pass # wrong param, at least addr or from or to
        sql += range_condition

        module_id = req.get_param('module_id', None)
        event_id = req.get_param('event_id', None)
        if module_id and event_id:
            assert ' ' not in module_id
            assert ' ' not in event_id
            type_condition = ' AND (module_id=:module_id AND event_id=:event_id)'
            sql += type_condition
            params['module_id'] = module_id
            params['event_id'] = event_id

        start_time = req.get_param('start_time', None)
        if start_time:
            assert type(int(start_time)) is int
            start_time_condition = ' AND timestamp>=:start_time'
            sql += start_time_condition
            params['start_time'] = start_time

        end_time = req.get_param('end_time', None)
        if end_time:
            assert type(int(end_time)) is int
            end_time_condition = ' AND timestamp<:end_time'
            sql += end_time_condition
            params['end_time'] = end_time

        # print(sql, params)
        data = []
        result = self.session.execute(sql, params)
        if sum:
            row = result.fetchone()
            resp.media = {'count': row[0]}
        else:
            for row in result:
                # print("result:", row)
                row = list(row)
                if row[4]:
                    row[4] = row[4].replace('"', '')
                if row[5]:
                    row[5] = row[5].replace('"', '')

                row_dict = {
                    'block_id': row[0],
                    'event_idx': row[1],
                    'module_id': row[2],
                    'event_id': row[3],
                    '_from': row[4],
                    '_to': row[5],
                    'amount': row[6],
                    'timestamp': row[7]
                }

                data.append(row_dict)
            resp.media = {'data': data}

event_map = {
    'staking_delegatorreward': settings.SEARCH_INDEX_STAKING_REWARD,
    'micropayment_claimpayment': settings.SEARCH_INDEX_MICROPAYMENT_CLAIMPAYMENT,
    'balances_transfer': settings.SEARCH_INDEX_BALANCETRANSFER,
    'operation_releasereward': settings.SEARCH_INDEX_RELEASE_REWARD,
    'uniques_transferred': settings.SEARCH_INDEX_UNIQUES_TRANSFERRED,
    'staking_npowmint': settings.SEARCH_INDEX_NPOW_MINT,
}

class TransactionResource2(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr', None)
        from_addr = req.get_param('from', None)
        to_addr = req.get_param('to', None)
        sum_option = str(req.get_param('sum')).lower() == 'true'

        # sql = 'SELECT block_id, event_idx, module_id, event_id, _from, _to, amount, timestamp FROM transaction WHERE'
        sql = 'SELECT block_id, event_idx, account_id FROM data_account_search_index WHERE'
        params = {}
        if addr:
            assert ' ' not in addr
            range_condition = ' (account_id = :from OR account_id = :to)'
            if addr.startswith('0x'):
                params['from'] = addr.replace('0x', '')
                params['to'] = addr.replace('0x', '')
            else:
                params['from'] = ss58_decode(addr)
                params['to'] = ss58_decode(addr)

        elif from_addr:
            assert ' ' not in from_addr
            range_condition = ' account_id = :from'
            if from_addr.startswith('0x'):
                params['from'] = from_addr.replace('0x', '')
            else:
                params['from'] = ss58_decode(from_addr)

        elif to_addr:
            assert ' ' not in to_addr
            range_condition = ' account_id = :to'
            if to_addr.startswith('0x'):
                params['to'] = to_addr.replace('0x', '')
            else:
                params['to'] = ss58_decode(to_addr)
        else:
            pass # wrong param, at least addr or from or to
        sql += range_condition

        module_id = req.get_param('module_id', None)
        event_id = req.get_param('event_id', None)
        if module_id and event_id:
            assert ' ' not in module_id
            assert ' ' not in event_id

            index_type_id = event_map.get('%s_%s' % (module_id.lower(), event_id.lower()))
            type_condition = ' AND index_type_id = :index_type_id'
            sql += type_condition
            params['index_type_id'] = index_type_id

        data = []
        sum_amount = 0
        sql += ' ORDER BY block_id DESC limit 600'    
        result = self.session.execute(sql, params)
        row_count = result.rowcount

        conditions = []
        if len(row_count) == 600:
            print('!testDEBUG ---> account')
            print(addr)
            print(from_addr)
            print(to_addr)
            print(sum_option)
            print(sql)
            print(result)
            
        for row in result:
            # print("result:", row)
            row = list(row)
            block_id = row[0]
            event_idx = row[1]
            if block_id is not None and event_idx is not None:
                conditions.append(' (block_id = %s AND event_idx = %s) ' % (block_id, event_idx))

        if conditions:
            sql = 'SELECT block_id, event_idx, module_id, event_id, attributes, block_datetime FROM data_event WHERE (' + 'OR'.join(conditions) + ')'

            start_time = req.get_param('start_time', None)
            if start_time:
                assert type(int(start_time)) is int
                start_time_condition = ' AND block_datetime >= :start_time'
                sql += start_time_condition
                params['start_time'] = datetime.fromtimestamp(int(start_time))

            end_time = req.get_param('end_time', None)
            if end_time:
                assert type(int(end_time)) is int
                end_time_condition = ' AND block_datetime < :end_time'
                sql += end_time_condition
                params['end_time'] = datetime.fromtimestamp(int(end_time))

            # print(sql)
            result = self.session.execute(sql, params)

            for row in result:
                row = list(row)
                module_id = row[2]
                event_id = row[3]
                index_type_id = event_map.get('%s_%s' % (module_id.lower(), event_id.lower()))
                # print('index_type_id', index_type_id, module_id, event_id)
                if index_type_id == settings.SEARCH_INDEX_STAKING_REWARD:
                    json_data = json.loads(row[4])
                    _from = None
                    try:
                        _to = json_data[0]['value']
                        amount = json_data[1]['value']
                    except:
                        _to = json_data[0]
                        amount = json_data[1]

                elif index_type_id == settings.SEARCH_INDEX_BALANCETRANSFER:
                    json_data = json.loads(row[4])
                    try:
                        _from = json_data[0]['value']
                        _to = json_data[1]['value']
                        amount = json_data[2]['value']
                    except:
                        _from = json_data[0]
                        _to = json_data[1]
                        amount = json_data[2]

                elif index_type_id == settings.SEARCH_INDEX_MICROPAYMENT_CLAIMPAYMENT:
                    json_data = json.loads(row[4])
                    try:
                        _from = json_data[0]['value']
                        _to = json_data[1]['value']
                        amount = json_data[2]['value']
                    except:
                        _from = json_data[0]
                        _to = json_data[1]
                        amount = json_data[2]

                elif index_type_id == settings.SEARCH_INDEX_RELEASE_REWARD:
                    json_data = json.loads(row[4])
                    _from = None
                    _to = json_data[0]
                    amount = json_data[1]

                elif index_type_id == settings.SEARCH_INDEX_UNIQUES_TRANSFERRED:
                    json_data = json.loads(row[4])
                    _from = json_data[2]
                    _to = json_data[3]
                    amount = '{},{}'.format(json_data[0], json_data[1]) # class, instance
                elif index_type_id == settings.SEARCH_INDEX_NPOW_MINT:
                    json_data = json.loads(row[4])
                    _from = None
                    _to = json_data[0]
                    amount = json_data[1]
                else:
                    continue

                row_dict = {
                    'block_id': row[0],
                    'event_idx': row[1],
                    'module_id': module_id,
                    'event_id': event_id,
                    '_from': _from,
                    '_to': _to,
                    'amount': str(amount),
                    'timestamp': int(row[5].timestamp())
                }

                data.append(row_dict)
                sum_amount += int(amount)

        if sum_option:
            resp.media = {'count': sum_amount}
        else:
            resp.media = {'data': data}

'''
const processArg = require('./processArg');
const config = require('../config/config');
const util = require('./utils');
const logger = require('../../common-js/log');
const chainDb = require('../libs/chainDb');
const LIST_QUERY = 'SELECT balance_free, timestamp FROM balance WHERE address = ?';
const START_TIME_CONDITION = 'AND timestamp >= ?';
const END_TIME_CONDITION = 'AND timestamp < ?';
const ORDER_BY = 'ORDER BY timestamp asc';
const BALANCE_HISTORY_PERIODS = 30; // 30 periods
exports.getBalanceHistory = async publicKey => {
  const testnetMode = processArg.isTestnetMode();
  const periodLength = testnetMode ? config.TESTNET_PERIOD_LENGTH : config.MAINNET_PERIOD_LENGTH;
  const now = Date.now();
  const end = util.getPeriodStart(testnetMode, now, 0);
  const start = end - periodLength * BALANCE_HISTORY_PERIODS;
  const map = await getBalanceMap(publicKey, start, end, testnetMode);
  const list = toBalanceList(map, start, end, periodLength);
  for (let i = 1; i < list.length; i++) {
    if (list[i].balance === '0') {
      list[i].balance = list[i - 1].balance;
    }
  }
  return {
    testnetMode,
    list,
  };
};
async function getBalanceMap(address, start, end, testnetMode) {
  const rows = await query(LIST_QUERY, address, start, end);
  if (!rows) {
    logger.error(`Failed to get rows for balance map`);
    return {};
  }
  return processRows(rows, testnetMode);
}
async function query(baseQuery, address, start, end) {
  let query = baseQuery;
  const params = [address];
  if (start) {
    query = `${query} ${START_TIME_CONDITION}`;
    params.push(start / 1000);
  }
  if (end) {
    query = `${query} ${END_TIME_CONDITION}`;
    params.push(end / 1000);
  }
  query = `${query} ${ORDER_BY}`;
  const rows = await chainDb.query(query, params);
  return rows;
}
function processRows(rows, testnetMode) {
  const map = {};
  rows.forEach(row => {
    const balance = (row.balance_free * config.AMOUNT_CONVERSION_RATE).toFixed(config.FUND_PRECISION);
    const timestamp = row.timestamp * 1000;
    const periodStart = util.getPeriodStart(testnetMode, timestamp, 0);
    map[periodStart] = balance;
  });
  return map;
}
function toBalanceList(map, start, end, periodLength) {
  const list = [];
  for (let timestamp = start; timestamp < end; timestamp += periodLength) {
    const balance = map[timestamp] || '0';
    list.push({
      timestamp,
      balance,
    });
  }
  return list.sort((a, b) => {
    return a.timestamp - b.timestamp;
  });
}
'''
class BalanceResource(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')

        sql = 'SELECT balance_free, timestamp FROM balance WHERE address = :addr'
        params = {}
        assert addr and ' ' not in addr
        if addr.startswith('0x'):
            params['addr'] = ss58_encode(addr[2:])
        else:
            params['addr'] = addr

        start_time = req.get_param('start_time', None)
        if start_time:
            assert type(int(start_time)) is int
            start_time_condition = ' AND timestamp>=:start_time'
            sql += start_time_condition
            params['start_time'] = start_time

        end_time = req.get_param('end_time', None)
        if end_time:
            assert type(int(end_time)) is int
            end_time_condition = ' AND timestamp<:end_time'
            sql += end_time_condition
            params['end_time'] = end_time

        sql += ' ORDER BY timestamp asc'
        # print(sql, params)
        data = []
        result = self.session.execute(sql, params)

        for row in result:
            # print("result:", row)
            row = list(row)
            if row[0] is None:
                row[0] = 0
            else:
                row[0] = int(row[0])
            row_dict = {
                'balance_free': row[0],
                'timestamp': row[1]
            }
            data.append(row_dict)
        resp.media = {'data': data}

'''
CREATE VIEW "balance" AS
select
  "account"."address" AS "address",
  "snapshot"."balance_total" AS "balance_total",
  "snapshot"."balance_free" AS "balance_free",
  "snapshot"."balance_reserved" AS "balance_reserved",
  unix_timestamp("block"."datetime") AS "timestamp"
from
  (
    (
      "data_account_info_snapshot" "snapshot"
      join "data_account" "account" on(("snapshot"."account_id" = "account"."id"))
    )
    join "data_block" "block" on(("snapshot"."block_id" = "block"."id"))
  )
'''
class BalanceResource2(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')

        sql = 'SELECT balance_free, block_datetime FROM data_account_info_snapshot WHERE account_id = :addr'
        params = {}
        assert addr and ' ' not in addr
        if addr.startswith('0x'):
            params['addr'] = addr[2:]
        else:
            params['addr'] = ss58_decode(addr)

        start_time = req.get_param('start_time', None)
        if start_time:
            assert type(int(start_time)) is int
            start_time_condition = ' AND block_datetime >= :start_time'
            sql += start_time_condition
            params['start_time'] = datetime.fromtimestamp(int(start_time))

        end_time = req.get_param('end_time', None)
        if end_time:
            assert type(int(end_time)) is int
            end_time_condition = ' AND block_datetime < :end_time'
            sql += end_time_condition
            params['end_time'] = datetime.fromtimestamp(int(end_time))

        sql += ' ORDER BY block_datetime ASC'
        # print(sql, params)
        data = []
        result = self.session.execute(sql, params)

        for row in result:
            # print("result:", row)
            row = list(row)
            if row[0] is None:
                row[0] = 0
            else:
                row[0] = int(row[0])
            row_dict = {
                'balance_free': row[0],
                'timestamp': int(row[1].timestamp())
            }
            data.append(row_dict)
        resp.media = {'data': data}


class TaxReport(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')
        sql = 'SELECT block_id, event_idx, account_id FROM data_account_search_index WHERE account_id = :addr AND index_type_id = :index_type_id'
        params = {
            'index_type_id': settings.SEARCH_INDEX_STAKING_REWARD
        }
        if addr.startswith('0x'):
            params['addr'] = addr[2:]
        else:
            params['addr'] = ss58_decode(addr)
        account_ss58 = ss58_encode(params['addr'])
        result = self.session.execute(sql, params)

        conditions = []
        for row in result:
            # print("result:", row)
            row = list(row)
            block_id = row[0]
            event_idx = row[1]
            if block_id is not None and event_idx is not None:
                conditions.append(' (block_id = %s AND event_idx = %s) ' % (block_id, event_idx))

        if conditions:
            sql = 'SELECT block_id, event_idx, attributes, block_datetime FROM data_event WHERE (' + 'OR'.join(conditions) + ')'

            start_time = req.get_param('start_time', None)
            if start_time:
                assert type(int(start_time)) is int
                start_time_condition = ' AND block_datetime >= :start_time'
                sql += start_time_condition
                params['start_time'] = datetime.fromtimestamp(int(start_time))

            end_time = req.get_param('end_time', None)
            if end_time:
                assert type(int(end_time)) is int
                end_time_condition = ' AND block_datetime < :end_time'
                sql += end_time_condition
                params['end_time'] = datetime.fromtimestamp(int(end_time))

            result = self.session.execute(sql, params)

            lines = ['Block-event, From, To, Amount(DPR), Datetime']
            for row in result:
                json_data = json.loads(row[2])
                try:
                    # _to = json_data[0]['value']
                    amount = json_data[1]['value']
                except:
                    # _to = json_data[0]
                    amount = json_data[1]
                lines.append('%s-%s, Deeper Chain, %s, %s, %s' % (row[0], row[1], account_ss58, amount/(10**18), row[3]))

        resp.body = '\n'.join(lines)
        # resp.content_length = 5
        resp.content_type = 'application/vnd.ms-excel'
        # resp.content_type = falcon.MEDIA_TEXT
        resp.downloadable_as = 'Tax Report for account %s.csv' % account_ss58


class StakingDelegateCount(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')
        sql = 'SELECT count(1) FROM data_account_search_index WHERE account_id = :addr AND index_type_id = :index_type_id'
        params = {
            'index_type_id': settings.SEARCH_INDEX_STAKING_REWARD
        }
        if addr.startswith('0x'):
            params['addr'] = addr[2:]
        else:
            params['addr'] = ss58_decode(addr)

        result = self.session.execute(sql, params)
        row = result.fetchone()
        staking_status = 'None' # 0: genesis gold, 1: genesis silver, 2: basic 1.0, 3: DPRB mining, 4: basic 2.0
        user_credit = get_user_credit(addr)
        if user_credit:
            campaign_id = user_credit['campaign_id']
            if campaign_id == 0 or campaign_id == 1:
                staking_status = 'Genesis'
            elif campaign_id == 2 or campaign_id == 3:
                staking_status = 'Basic Mining 1.0'
            elif campaign_id == 4:
                staking_status = 'Basic Mining 2.0'
        resp.media = {'count': row[0], 'staking_status': staking_status}

def get_user_credit(addr):
    req_url = "{}/pallets/credit/storage/UserCredit?key1={}".format(settings.SIDECAR_API_URL, addr)
    result = requests.get(req_url)
    if result.status_code != 200:
        return None
    else:
        result_body = result.json()
        if not 'value' in result_body or not result_body['value']:
            return None
        block_id = int(result_body['at']['height']) if 'at' in result_body and result_body['at'] and 'height' in result_body['at'] else 0
        credit = int(result_body['value']['credit']) if 'value' in result_body and result_body['value'] and 'credit' in result_body['value'] else 0
        campaign_id = int(result_body['value']['campaignId']) if 'value' in result_body and result_body['value'] and 'campaignId' in result_body['value'] else 0
        return {
            'block_id': block_id,
            'credit': credit,
            'campaign_id': campaign_id
        }

class CurrentUserCredit(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')
        user_credit = get_user_credit(addr)
        if not user_credit:
            resp.media = {'block_id': 0, 'credit': 0}
        else:
            resp.media = {'block_id': user_credit['block_id'], 'credit': user_credit['credit']}

def get_user_account(addr):
    req_url = "{}/pallets/system/storage/Account?key1={}".format(settings.SIDECAR_API_URL, addr)
    result = requests.get(req_url)
    if result.status_code != 200:
        return None
    else:
        result_body = result.json()
        if not 'value' in result_body or not result_body['value']:
            return None
        block_id = int(result_body['at']['height']) if 'at' in result_body and result_body['at'] and 'height' in result_body['at'] else 0
        nonce = int(result_body['value']['nonce']) if 'value' in result_body and result_body['value'] and 'nonce' in result_body['value'] else 0
        try:
            free = int(result_body['value']['data']['free'])
            reserved = int(result_body['value']['data']['reserved'])
        except KeyError:
            print('get_user_account no balance info {}'.format(result_body['value']))
            free = 0
            reserved = 0

        return {
            'block_id': block_id,
            'nonce': nonce,
            'free': free,
            'reserved': reserved,
        }

class CurrentUserAccount(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')
        user_account = get_user_account(addr)
        if not user_account:
            resp.media = {'block_id': 0, 'account': {'nonce': 0, 'free': 0, 'reserved': 0}}
        else:
            resp.media = {'block_id': user_account['block_id'], 'account': user_account}

class CurrentUserReleaseTime(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr')
        req_url = "{}/pallets/operation/storage/accountsReleaseInfo?key1={}".format(settings.SIDECAR_API_URL, addr)
        result = requests.get(req_url)
        if result.status_code != 200:
            resp.media = {'block_id': 0, 'release_time': ''}
        else:
            result_body = result.json()
            block_id = int(result_body['at']['height']) if 'at' in result_body and result_body['at'] and 'height' in result_body['at'] else 0
            release_time = ''
            if result_body['value'] != None:
                release_time = datetime.fromtimestamp(int(result_body['value']['basicInfo']['startReleaseMoment']) / 1000).isoformat()
            resp.media = {'block_id': block_id, 'release_time': release_time}

class OracleResource(BaseResource):
    def on_get(self, req, resp, **kwargs):
        sql = 'select value, updated_at from dpr_ezc_oracles order by id desc limit 1';
        result = self.session.execute(sql)
        row = result.fetchone()
        if row:
            resp.media = {'oracle': int(row[0]), 'updated_at': row[1].isoformat()}
        else:
            resp.media = {'oracle': 0, 'updated_at': ''}

# {
#     "id": 0,
#     "jsonrpc": "2.0",
#     "method": "eth_call",
#     "params": [
#         {
#             "data": "0x82295d9b0000000000000000000000007a5b2024e179b312b924ff02f4c27b5df5326601",
#             "to": "0xbca8f0ed708176383806b76cf98822c9e9fbd033"
#         },
#         "latest"
#     ]
# }
class NpowResource(BaseResource):
    def on_get(self, req, resp, **kwargs):
        addr = req.get_param('addr') # evm address
        if len(addr) != 42 or not addr.startswith('0x'): # ensure evm address
            resp.media = {'error': 'addr should starts with 0x and has length 42'}
            resp.status = falcon.HTTP_400
            return
        # check method prefix online
        payload = {
            'id': 0,
            'jsonrpc': '2.0',
            'method': 'eth_call',
            'params': [{'data': '0x82295d9b000000000000000000000000{}'.format(addr[2:]), 'to': settings.EVM_DEP_ADDRESS}, 'latest'],
        }
        res = requests.post(settings.EVM_RPC_URL, json=payload)
        res_body = json.loads(res.text)
        day = int(res_body['result'], base=16)
        sql = 'select COALESCE(sum(ezc), 0), COALESCE(sum(dpr), 0) from dpr_ezc_rewards where eth_addr=:eth_addr and day >= :day';
        sum_result = self.session.execute(sql, {'eth_addr': addr, 'day': day})
        sum_row = sum_result.fetchone()
        resp.media = {'addr': addr, 'ezc': int(sum_row[0]), 'dpr': int(sum_row[1])}
