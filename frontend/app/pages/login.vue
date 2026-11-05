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
  <div class="login">
    <form class="login-form" @submit.prevent="login">
      <p class="wordmark">Attack<em>Lens</em></p>
      <label>
        <span>Password</span>
        <input v-model="password" type="password" autocomplete="current-password" required autofocus />
      </label>
      <p v-if="failure" class="note" role="alert">{{ failure }}</p>
      <button class="link" type="submit" :disabled="busy">Enter</button>
    </form>
  </div>
</template>
