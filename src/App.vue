<template>
  <div id="app">
    <NitrokeyWebcryptDemo msg="Nitrokey Webcrypt Demo"/>
  </div>
</template>

<script lang="ts">

import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'
// import './custom.scss'
import { Component, Vue } from 'vue-property-decorator';
import NitrokeyWebcryptDemo from './components/NitrokeyWebcryptDemo.vue';

// import Vue from 'vue'
import { BootstrapVue, IconsPlugin } from 'bootstrap-vue'
// Install BootstrapVue
Vue.use(BootstrapVue)
// Optionally install the BootstrapVue icon components plugin
Vue.use(IconsPlugin)

import { LayoutPlugin, TabsPlugin, FormPlugin } from 'bootstrap-vue'
Vue.use(LayoutPlugin)
Vue.use(TabsPlugin)
Vue.use(FormPlugin)

import { ProgressPlugin } from 'bootstrap-vue'
Vue.use(ProgressPlugin)

@Component({
  components: {
    NitrokeyWebcryptDemo,
  },
})
export default class App extends Vue {}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
  padding-bottom: 100px;
}
</style>
