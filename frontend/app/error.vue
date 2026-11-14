<script setup lang="ts">
import type { NuxtError } from '#app'

const props = defineProps<{ error: NuxtError }>()

const missing = computed(() => props.error.statusCode === 404)

useHead({ title: () => `${props.error.statusCode} · AttackLens` })
</script>

<template>
  <div class="gate">
    <AsciiField class="backdrop" />
    <main class="gate-panel">
      <p class="t-data text-muted">{{ error.statusCode }}</p>
      <h1 class="t-heading-m">{{ missing ? 'Nothing at this address.' : 'Something went wrong.' }}</h1>
      <p class="t-body-m text-secondary">{{ missing ? 'This page does not exist.' : error.statusMessage || 'The dashboard could not show this page.' }}</p>
      <button class="btn btn-primary" type="button" @click="clearError({ redirect: '/' })">Back to the brief</button>
    </main>
  </div>
</template>
