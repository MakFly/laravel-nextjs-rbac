<script setup lang="ts">
import { Check, User, ShieldCheck, TrendingUp, Settings } from 'lucide-vue-next'

defineProps<{
  currentStep: number
  completedSteps: number[]
}>()

const steps = [
  { step: 1, title: 'Personal Info', icon: User },
  { step: 2, title: 'Identity', icon: ShieldCheck },
  { step: 3, title: 'Financial', icon: TrendingUp },
  { step: 4, title: 'Operations', icon: Settings },
]
</script>

<template>
  <div class="flex w-full items-start gap-2" role="group" aria-label="progress">
    <template v-for="(s, index) in steps" :key="s.step">
      <div class="relative flex w-full flex-col items-center gap-2">
        <div class="flex flex-col items-center gap-1.5">
          <div
            class="flex size-8 items-center justify-center rounded-full border-2 transition-colors"
            :class="{
              'border-primary bg-primary text-primary-foreground': completedSteps.includes(s.step) || currentStep === s.step,
              'border-muted bg-muted text-muted-foreground': currentStep !== s.step && !completedSteps.includes(s.step),
            }"
          >
            <Check v-if="completedSteps.includes(s.step)" class="size-4" />
            <component :is="s.icon" v-else class="size-4" />
          </div>
          <span
            class="text-xs sm:text-sm"
            :class="{
              'text-primary font-semibold': currentStep === s.step,
              'text-muted-foreground': currentStep !== s.step && !completedSteps.includes(s.step),
              'text-foreground': completedSteps.includes(s.step) && currentStep !== s.step,
            }"
          >
            {{ s.title }}
          </span>
        </div>
      </div>

      <div
        v-if="index < steps.length - 1"
        class="h-0.5 flex-1 rounded-full mt-4"
        :class="{
          'bg-primary': completedSteps.includes(s.step),
          'bg-muted': !completedSteps.includes(s.step),
        }"
      />
    </template>
  </div>
</template>
