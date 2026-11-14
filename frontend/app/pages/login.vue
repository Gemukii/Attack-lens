<script setup lang="ts">
const password = ref('')
const failure = ref<string | null>(null)
const busy = ref(false)

const login = async () => {
  busy.value = true
  failure.value = null
  try {
    await $fetch('/auth/login', { method: 'POST', body: { password: password.value } })
    await navigateTo('/', { external: true })
  } catch (cause: unknown) {
    failure.value = (cause as { statusMessage?: string }).statusMessage ?? 'Unable to log in.'
    password.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="gate">
    <AsciiField class="backdrop" />
    <form class="gate-panel" @submit.prevent="login">
      <p class="wordmark">AttackLens</p>
      <label class="gate-field">
        <span class="t-label">Password</span>
        <input v-model="password" class="field t-body-m" type="password" autocomplete="current-password" required autofocus />
      </label>
      <p v-if="failure" class="gate-failure t-body-s" role="alert">
        <span class="lamp lamp-off" aria-hidden="true" />{{ failure }}
      </p>
      <button class="btn btn-primary" type="submit" :disabled="busy">
        <template v-if="busy"><span class="busy" aria-hidden="true" />Checking</template>
        <template v-else>Enter</template>
      </button>
    </form>
  </div>
</template>
