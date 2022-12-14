// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/', name: 'jobs', component: {
  template: '#page-jobs',
  data() { return {
    i18n: this.$root.i18n,
    jobs: [],
    headers: [
      { text: this.$root.i18n.id, value: 'id' },
      { text: this.$root.i18n.dateQueued, value: 'createTime' },
      { text: this.$root.i18n.dateUpdated, value: 'updateTime' },
      { text: this.$root.i18n.sensorId, value: 'sensorId' },
      { text: this.$root.i18n.status, value: 'status' },
    ],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    dialog: false,
    form: {
      valid: false,
      sensorId: null,
      srcIp: null,
      srcPort: null,
      dstIp: null,
      dstPort: null,
      beginTime: null,
      endTime: null,
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
  }},
  created() {
    Vue.filter('formatJobStatus', this.formatJobStatus);
    Vue.filter('formatJobUpdateTime', this.formatJobUpdateTime);
    Vue.filter('colorJobStatus', this.colorJobStatus);
    this.loadData()
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('jobs');
        this.$root.log(response.data.data);
        this.jobs = response.data.data;
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("job", this.updateJob);
    },
    saveLocalSettings() {
      localStorage['settings.jobs.sortBy'] = this.sortBy;
      localStorage['settings.jobs.sortDesc'] = this.sortDesc;
      localStorage['settings.jobs.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.jobs.sortBy']) {
        this.sortBy = localStorage['settings.jobs.sortBy'];
        this.sortDesc = localStorage['settings.jobs.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.jobs.itemsPerPage']);
      }
    },
    updateJob(job) {
      for (var i = 0; i < this.jobs.length; i++) {
        if (this.jobs[i].id == job.id) {
          this.$set(this.jobs, i, job);
          break;
        }
      }
    },
    submitAddJob(event) {
      this.addJob(this.form.sensorId, this.form.srcIp, this.form.srcPort, this.form.dstIp, this.form.dstPort, this.form.beginTime, this.form.endTime);
      this.dialog = false;
      this.form.sensorId = null;
      this.form.srcIp = null;
      this.form.srcPort = null;
      this.form.dstIp = null;
      this.form.dstPort = null;
      this.form.beginTime = null;
      this.form.endTime = null;
    },
    async addJob(sensorId, srcIp, srcPort, dstIp, dstPort, beginTime, endTime) {
      try {
        if (!sensorId) {
          this.$root.showError(this.i18n.sensorIdRequired);
        } else {
          const response = await this.$root.papi.post('job', {
            sensorId: sensorId,
            filter: {
              srcIp: srcIp,
              srcPort: parseInt(srcPort),
              dstIp: dstIp,
              dstPort: parseInt(dstPort),
              beginTime: new Date(beginTime),
              endTime: new Date(endTime)
            }
          });
          this.jobs.push(response.data);
        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
    formatJobUpdateTime(job) {
      var time = "";
      if (job.status == 1) {
        time = job.completeTime;
      } else if (job.status == 2) {
        time = job.failTime;
      }
      return time;
    },
    formatJobStatus(job) {
      var status = this.i18n.pending;
      if (job.status == 1) {
        status = this.i18n.completed;
      } else if (job.status == 2) {
        status = this.i18n.incomplete;
      }
      return status;
    },
    colorJobStatus(job) {
      var color = "gray";
      if (job.status == 1) {
        color = "success";
      } else if (job.status == 2) {
        color = "info";
      }
      return color;
    }
  }
}});
