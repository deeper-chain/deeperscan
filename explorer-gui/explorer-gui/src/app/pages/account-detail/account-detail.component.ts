/*
 * Polkascan Explorer GUI
 *
 * Copyright 2018-2020 openAware BV (NL).
 * This file is part of Polkascan.
 *
 * Polkascan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Polkascan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
 *
 * account-detail.component.ts
 */

import {ChangeDetectorRef, Component, OnDestroy, OnInit} from '@angular/core';
import {DocumentCollection} from 'ngx-jsonapi';
import {Extrinsic} from '../../classes/extrinsic.class';
import {Event} from '../../classes/event.class';
import {BalanceTransferService} from '../../services/balance-transfer.service';
import {ExtrinsicService} from '../../services/extrinsic.service';
import {ActivatedRoute, ParamMap} from '@angular/router';
import {Observable, Subscription} from 'rxjs';
import {Account} from '../../classes/account.class';
import {AccountService} from '../../services/account.service';
import {switchMap} from 'rxjs/operators';
import {BalanceTransfer} from '../../classes/balancetransfer.class';
import {AppConfigService} from '../../services/app-config.service';
import {AccountIndexService} from '../../services/account-index.service';
import {EventService} from '../../services/event.service';
import {BlockTotal} from '../../classes/block-total.class';
import {BlockTotalService} from '../../services/block-total.service';
import {Chart} from 'angular-highcharts';
import {RuntimeModule} from '../../classes/runtime-module.class';
import {RuntimeCall} from '../../classes/runtime-call.class';
import {RuntimeModuleService} from '../../services/runtime-module.service';
import {RuntimeCallService} from '../../services/runtime-call.service';
import {SS58} from '../../classes/ss58.class';
import {blake2b} from 'blakejs';
import {environment} from "../../../environments/environment";


@Component({
  selector: 'app-account-detail',
  templateUrl: './account-detail.component.html',
  styleUrls: ['./account-detail.component.scss']
})
export class AccountDetailComponent implements OnInit, OnDestroy {

  private networkSubscription: Subscription;

  public balanceTransfers: DocumentCollection<BalanceTransfer>;
  public extrinsics: DocumentCollection<Extrinsic>;

  public slashes: DocumentCollection<Event>;
  public rewards: DocumentCollection<Event>;
  public creditUpdates: DocumentCollection<Event>;
  public councilActivity: DocumentCollection<Event>;
  public memberActivity: DocumentCollection<Extrinsic>;
  public electionActivity: DocumentCollection<Event>;
  public imOnlineActivity: DocumentCollection<Event>;
  public stakingBondActivity: DocumentCollection<Extrinsic>;
  public stakingSessionsActivity: DocumentCollection<Event>;
  public treasuryActivity: DocumentCollection<Extrinsic>;
  public identityActivity: DocumentCollection<Event>;
  public proposalActivity: DocumentCollection<Extrinsic>;
  public referendumActivity: DocumentCollection<Extrinsic>;
  public techcommActivity: DocumentCollection<Extrinsic>;
  public authoredBlocks: DocumentCollection<BlockTotal>;
  public accountLifecycle: DocumentCollection<Event>;

  public runtimeModules: DocumentCollection<RuntimeModule>;
  public runtimeCalls: DocumentCollection<RuntimeCall>;
  public filterModule: RuntimeModule = null;
  public filterCall: RuntimeCall = null;

  public balanceTransfersPage = 1;
  public extrinsicsPage = 1;
  public slashesPage = 1;
  public rewardsPage = 1;
  public councilActivityPage = 1;
  public electionActivityPage = 1;
  public memberActivityPage = 1;
  public stakingBondActivityPage = 1;
  public stakingSessionsActivityPage = 1;
  public treasuryActivityPage = 1;
  public imOnlineActivityPage = 1;
  public identityActivityPage = 1;
  public proposalActivityPage = 1;
  public referendumActivityPage = 1;
  public techcommActivityPage = 1;
  public authoredBlocksPage = 1;
  public accountLifecyclePage = 1;

  public accountId: string;

  public account$: Observable<Account>;

  public resourceNotFound: boolean;

  public networkURLPrefix: string;
  public networkTokenDecimals: number;
  public networkTokenSymbol: string;

  public currentTab: string;
  private fragmentSubsription: Subscription;
  private queryParamsSubsription: Subscription;

  public balanceHistoryChart: Chart;
  private balanceHistoryChartOptions: {};
  private balanceHistoryChartData = {};

  private ws: WebSocket = null;
  private ss58: SS58 = null;
  private staking: boolean = false;
  private rewardCount: number = 0;
  private stakingStatus: string = '';
  private currentUserCredit: number = 0;
  private currentUserReleaseTime: string = '';

  constructor(
    private balanceTransferService: BalanceTransferService,
    private extrinsicService: ExtrinsicService,
    private eventService: EventService,
    private runtimeModuleService: RuntimeModuleService,
    private runtimeCallService: RuntimeCallService,
    private blockTotalService: BlockTotalService,
    private accountService: AccountService,
    private accountIndexService: AccountIndexService,
    private appConfigService: AppConfigService,
    private activatedRoute: ActivatedRoute,
    private ref: ChangeDetectorRef
  ) { }

  ngOnInit() {

    this.resourceNotFound = false;
    this.currentTab = 'transactions';

    this.fragmentSubsription = this.activatedRoute.fragment.subscribe(value => {
      if ([
        'roles', 'transactions', 'slashes', 'transfers', 'rewards', 'council', 'election', 'member', 'techcomm', 'balance-history',
        'bonding', 'imonline', 'identity', 'authoredblocks', 'lifecycle', 'treasury', 'proposals', 'referenda', 'credit-history',
        'sessions'
      ].includes(value)) {
        this.currentTab = value;
      } else {
        this.currentTab = 'transactions';
      }
    });

    this.networkSubscription = this.appConfigService.getCurrentNetwork().subscribe( network => {

      this.networkURLPrefix = this.appConfigService.getUrlPrefix();

      this.networkTokenDecimals = +network.attributes.token_decimals;
      this.networkTokenSymbol = network.attributes.token_symbol;

      this.balanceHistoryChartOptions = {
        colors: ['#3c88ed'],
        chart: {
          type: 'area',
          zoomType: 'x',
          height: null
        },
        title: {
          text: '',
          style: {fontSize: '12px'}
        },
        credits: {
          enabled: false
        },
        xAxis: {
          title: {
            text: 'Block number'
          }
        },
        yAxis: {
          title: {
            text: network.attributes.token_symbol
          }
        },
        legend: {
          enabled: false
        },
        plotOptions: {
          area: {
            fillColor: {
              linearGradient: {
                x1: 0,
                y1: 0,
                x2: 0,
                y2: 1
              },
              stops: [
                [0, '#' + network.attributes.color_code],
                [1, '#fff']
              ]
            },
            marker: {
              radius: 2
            },
            lineWidth: 1,
            states: {
              hover: {
                lineWidth: 1
              }
            },
            threshold: null
          }
        },
        series: [],
        tooltip: {
          shared: true,
          useHTML: true,
          // headerFormat: '<small>{point.key}</small><table>',
          // pointFormat: '<tr><td style="color: {series.color}">{series.name}: </td>' +
          //   '<td style="text-align: right"><b>{point.y} DPR</b> {series.data} {point.index} {series.options.data}</td></tr>',
          // footerFormat: '</table>',
          // valueDecimals: 2,
          pointFormatter: function() {
            return '<span style="color: ' + this.series.color + '">' + this.series.name + '</span> ' +
                   this.y + ' DPR<br/>'+ 
                   '<span style="color: ' + this.series.color + '">Datetime</span> ' +
                   this.series.options.data[this.index][2]
          }
        }
      };

      this.account$ = this.activatedRoute.paramMap.pipe(
        switchMap((params: ParamMap) => {
          this.accountId = params.get('id');
          return this.accountService.get(params.get('id'));
        })
      );

      this.account$.subscribe(val => {
        if (val.attributes.address) {

          this.accountId = val.attributes.address;

          // reset tabs
          this.slashes = null;
          this.rewards = null;
          this.councilActivity = null;
          this.memberActivity = null;
          this.electionActivity = null;
          this.imOnlineActivity = null;
          this.stakingBondActivity = null;
          this.stakingSessionsActivity = null;
          this.treasuryActivity = null;
          this.identityActivity = null;
          this.proposalActivity = null;
          this.referendumActivity = null;
          this.techcommActivity = null;
          this.authoredBlocks = null;
          this.accountLifecycle = null;

          this.balanceHistoryChartData = val.attributes.balance_history[0];
          this.renderChart();
          // this.chart.addSeries(val.attributes.balance_history[1], true, true);
          // this.chart.addSeries(val.attributes.balance_history[2], true, true);

          this.queryParamsSubsription = this.activatedRoute.queryParams.subscribe(queryParams => {
            this.extrinsicsPage = +queryParams.extrinsicsPage || 1;
            this.getTransactions(this.extrinsicsPage);

            this.balanceTransfersPage = +queryParams.balanceTransfersPage || 1;
            this.getBalanceTransfers(this.balanceTransfersPage);

            this.identityActivityPage = +queryParams.identityActivityPage || 1;
            this.getIdentityActivity(this.identityActivityPage);

            this.accountLifecyclePage = +queryParams.accountLifecyclePage || 1;
            this.getAccountLifecycle(this.accountLifecyclePage);

            this.getCreditUpdateEvents();

            this.proposalActivityPage = +queryParams.proposalActivityPage || 1;
            this.getProposalActivity(this.proposalActivityPage);

            this.referendumActivityPage = +queryParams.referendumActivityPage || 1;
            this.getReferendumActivity(this.referendumActivityPage);

            if (val.attributes.was_validator || val.attributes.was_nominator) {

              // Validator & Nominator tabs
              this.rewardsPage = +queryParams.rewardsPage || 1;
              this.getRewardsEvents(this.rewardsPage);
              this.slashesPage = +queryParams.slashesPage || 1;
              this.getSlashEvents(this.slashesPage);
              this.stakingBondActivityPage = +queryParams.stakingBondActivityPage || 1;
              this.getStakingBondActivity(this.stakingBondActivityPage);
              this.stakingSessionsActivityPage = +queryParams.stakingSessionsActivityPage || 1;
              this.getStakingSessionsActivity(this.stakingSessionsActivityPage);
              this.imOnlineActivityPage = +queryParams.imOnlineActivityPage || 1;
              this.getImOnlineActivity(this.imOnlineActivityPage);
              this.authoredBlocksPage = +queryParams.authoredBlocksPage || 1;
              this.getAuthoredBlocks(this.authoredBlocksPage);
            }

            if (val.attributes.was_council_member) {
              // Council member tabs
              this.councilActivityPage = +queryParams.councilPage || 1;
              this.getCouncilActivity(this.councilActivityPage);

              this.electionActivityPage = +queryParams.electionActivityPage || 1;
              this.getElectionActivity(this.electionActivityPage);

              this.treasuryActivityPage = +queryParams.treasuryActivityPage || 1;
              this.getTreasuryActivity(this.treasuryActivityPage);

              this.memberActivityPage = +queryParams.memberActivityPage || 1;
              this.getMemberActivity(this.memberActivityPage);
            }

            if (val.attributes.was_tech_comm_member) {
              this.techcommActivityPage = +queryParams.techcommActivityPage || 1;
              this.getTechCommActivity(this.techcommActivityPage);
            }
          });
        }
      }, error => {
        if (error.status === 404) {
          this.resourceNotFound = true;
        }
      });

      const params = {
        page: {number: 0, size: 100},
        remotefilter: {latestRuntime: true},
      };

      this.runtimeModuleService.all(params).subscribe(runtimeModules => {
        this.runtimeModules = runtimeModules;
      });

    });

    this.ss58 = new SS58();
    if(window.location.hostname == 'www.deeperscan.io'){
      this.connect('wss://mainnet-deeper-chain.deeper.network');
    }else{
      this.connect('wss://mainnet-dev.deeper.network');
    }

    // console.log(environment.jsonApiRootUrl);
    fetch(environment.jsonApiRootUrl+'/deeper/staking_delegate_count?addr='+this.accountId)
      .then(response => response.json())
      .then(data => {
        this.rewardCount = data.count;
        this.stakingStatus = data.staking_status;
      })
      .catch((error) => {
        console.error('Error:', error);
      });

    fetch(environment.jsonApiRootUrl+'/deeper/current_user_credit?addr='+this.accountId)
      .then(response => response.json())
      .then(data => {
        // console.log('Success:', data);
        this.currentUserCredit = data.credit;
      })
      .catch((error) => {
        console.error('Error:', error);
      });

    fetch(environment.jsonApiRootUrl+'/deeper/current_user_release_time?addr='+this.accountId)
      .then(response => response.json())
      .then(data => {
        // format time with tz
        this.currentUserReleaseTime = data.release_time;
      })
      .catch((error) => {
        console.error('Error:', error);
      });
  }

  selectModule(module) {
    this.filterModule = module;
    this.filterCall = null;

    if (module !== null) {
      const params = {
        page: {number: 0, size: 100},
        remotefilter: {latestRuntime: true, module_id: this.filterModule},
      };

      this.runtimeCallService.all(params).subscribe(runtimeCalls => {
        this.runtimeCalls = runtimeCalls;
      });
    } else {
      this.runtimeCalls = null;
    }
  }

  selectCall(call) {
    this.filterCall = call;
  }

  applyFilters() {
    this.extrinsicsPage = 1;
    this.getTransactions(1);
  }

  public renderChart() {
    this.balanceHistoryChart = new Chart(this.balanceHistoryChartOptions);
    // @ts-ignore
    this.balanceHistoryChart.addSeries(this.balanceHistoryChartData, true, true);
  }

  public formatBalance(balance: number) {
    return balance / Math.pow(10, this.networkTokenDecimals);
  }

  public getTransactions(page: number) {
    if(this.filterModule && this.filterCall){
      this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, module_id: this.filterModule, call_id: this.filterCall},
      }).subscribe(extrinsics => {
        this.extrinsics = extrinsics;
      });
    }else{
      this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId},
      }).subscribe(extrinsics => {
        this.extrinsics = extrinsics;
      });
    }
  }

  public getBalanceTransfers(page: number) {
    this.balanceTransferService.all({
      remotefilter: {address: this.accountId},
      page: {number: page}
    }).subscribe(balanceTransfers => (this.balanceTransfers = balanceTransfers));
  }

  public getRewardsEvents(page: number) {
    this.eventService.all({
      page: {number: page, size: 25},
      remotefilter: {address: this.accountId, search_index: '39'},
    }).subscribe(events => {
      this.rewards = events;
    });
  }

  public getCreditUpdateEvents() {
    this.eventService.all({
      //  page: {number: page, size: 25},
      remotefilter: {address: this.accountId, search_index: '43'},
    }).subscribe(events => {
      this.creditUpdates = events;
    });
  }

  public getSlashEvents(page: number) {
    this.eventService.all({
      page: {number: page, size: 25},
      remotefilter: {address: this.accountId, search_index: '1'},
    }).subscribe(events => {
      this.slashes = events;
    });
  }

  public getCouncilActivity(page: number) {
     this.eventService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '4,5'},
      }).subscribe(events => {
        this.councilActivity = events;
      });
  }

  public getMemberActivity(page: number) {
    this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '25,26,27'},
      }).subscribe(extrinsics => {
        this.memberActivity = extrinsics;
      });
  }

  public getElectionActivity(page: number) {
      this.eventService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '23,24'},
      }).subscribe(events => {
        this.electionActivity = events;
      });
  }

  public getStakingBondActivity(page: number) {
     this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '6,7,8,10,11,12,19'},
      }).subscribe(extrinsics => {
        this.stakingBondActivity = extrinsics;
      });
  }

  public getStakingSessionsActivity(page: number) {
     this.eventService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: 38},
      }).subscribe(events => {
        this.stakingSessionsActivity = events;
      });
  }

  public getImOnlineActivity(page: number) {
   this.eventService.all({
      page: {number: page, size: 25},
      remotefilter: {address: this.accountId, search_index: '3,9'},
    }).subscribe(events => {
      this.imOnlineActivity = events;
    });
  }

  public getIdentityActivity(page: number) {
     this.eventService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '13,14,15,16,17,18,20'},
      }).subscribe(events => {
        this.identityActivity = events;
      });
  }

  public getProposalActivity(page: number) {
     this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '31,32'},
      }).subscribe(extrinsics => {
        this.proposalActivity = extrinsics;
      });
  }

  public getReferendumActivity(page: number) {
     this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '29,30'},
      }).subscribe(extrinsics => {
        this.referendumActivity = extrinsics;
      });
  }

  public getTechCommActivity(page: number) {
     this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '33,34'},
      }).subscribe(extrinsics => {
        this.techcommActivity = extrinsics;
      });
  }

  public getTreasuryActivity(page: number) {
     this.extrinsicService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: 28},
      }).subscribe(extrinsics => {
        this.treasuryActivity = extrinsics;
      });
  }

  public getAuthoredBlocks(page: number) {
    this.blockTotalService.all({
      page: {number: page, size: 25},
      remotefilter: {author: this.accountId},
    }).subscribe(blocks => this.authoredBlocks = blocks);
  }

  public getAccountLifecycle(page: number) {
     this.eventService.all({
        page: {number: page, size: 25},
        remotefilter: {address: this.accountId, search_index: '21,22'},
      }).subscribe(events => {
        this.accountLifecycle = events;
      });
  }

  ngOnDestroy() {
    // Will clear when component is destroyed e.g. route is navigated away from.
    this.networkSubscription.unsubscribe();
    if (this.fragmentSubsription) {
      this.fragmentSubsription.unsubscribe();
    }
    if (this.queryParamsSubsription) {
      this.queryParamsSubsription.unsubscribe();
    }
  }

  public formatUrl(url) {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return url;
    } else {
      return 'http://' + url;
    }
  }

  public connect(url: string): void {
    this.ws = new WebSocket(url);
    this.ws.onopen = this.onOpen.bind(this);
    this.ws.onmessage = this.onMessage.bind(this);
    this.ws.onerror = this.onError.bind(this);
    this.ws.onclose = this.onClose.bind(this);
  }

  public onOpen(event: any): void {
    console.log("connected");
    this.ws.send('{"jsonrpc": "2.0", "method": "chain_getHead", "params": [], "id": 1}');
  }

  public onMessage(event: any): void {
    // console.log("on message", event.data);
    const message = JSON.parse(event.data);
    if(message.id == 1){
      var user_hex = this.ss58.ss58_decode(this.accountId);
      var user_hash = this.ss58.arraytoHex(blake2b(this.ss58.hexToArray(user_hex), null, 16));
      // var module_hash = this.ss58.arraytoHex(xxhash128(new TextEncoder().encode("Staking"), null, 16));
      // var function_hash = this.ss58.arraytoHex(xxhash128(new TextEncoder().encode("Delegators"), null, 16));
      // console.log(module_hash, function_hash);
      const block_hash = message.result;
  
      this.ws.send('{"jsonrpc": "2.0", "method": "state_getStorageAt", "params": ["0x5f3e4907f716ac89b6347d15ececedcae1c5df6d2773f08c7b6b1b6d0139c22a'+ user_hash + user_hex +'", "'+ block_hash+ '"], "id": 2}');
    }else if(message.id == 2){
      // console.log(message.result.slice(-1));
      if(message.result && message.result.slice(-1) == '1'){
        this.staking = true;
      }
    }
  }

  public onError(event: any): void {
    console.log(JSON.stringify(event.data));
  }

  public onClose(event: any): void {
    console.log(JSON.stringify(event.data));
  }
}
