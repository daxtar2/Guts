import { createStore } from 'vuex'

export default createStore({
  state: {
    config: null,
    configUpdated: false
  },
  mutations: {
    setConfig(state, config) {
      state.config = config
      state.configUpdated = true
    }
  },
  actions: {
    async fetchConfig({ commit }) {
      try {
        const response = await axios.get('/api/config/filter')
        commit('setConfig', response.data)
      } catch (error) {
        console.error('Error fetching config:', error)
      }
    }
  }
}) 