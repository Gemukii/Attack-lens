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
  <div class="room login">
    <form class="login-form develop" @submit.prevent="login">
      <div class="brand">
        <svg viewBox="-12 -12 24 24" aria-hidden="true">
          <circle r="11" fill="none" stroke="var(--paper)" stroke-width="1.5" />
          <polygon points="0,-5 4.8,-1.5 3,4 -3,4 -4.8,-1.5" fill="var(--safelight)" />
        </svg>
        AttackLens
      </div>
      <label>
        <span class="eyebrow">Password</span>
        <input v-model="password" type="password" autocomplete="current-password" required autofocus />
      </label>
      <p v-if="failure" class="note" role="alert">{{ failure }}</p>
      <button class="button primary" type="submit" :disabled="busy">Open the lab</button>
    </form>
  </div>
</template>
