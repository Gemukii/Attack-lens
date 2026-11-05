import type { AttackPathReport, ExposureReport, Finding, ScanResults } from '~/types/scan'
import { byRisk, isOpen } from '~/utils/findings'

export interface Brief {
  headline: string
  lead: string
}

const WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven']
const count = (value: number) => WORDS[value] ?? String(value)

// What a person would say after reading the results, rather than a table of numbers.
export const writeBrief = (
  scan: ScanResults | null,
  paths: AttackPathReport | null,
  exposure: ExposureReport | null,
  seenFromInside = true,
): Brief => {
  if (!scan) {
    return {
      headline: 'Nothing has been measured yet.',
      lead: 'Run a first scan to see what this machine shows to the network.',
    }
  }
  if (scan.status === 'no_response') {
    return {
      headline: `${scan.target} did not answer.`,
      lead: 'It is down, or filters everything. Nothing was observed, so this says nothing about its safety.',
    }
  }

  // Attack paths need the inside view: without it, finding none proves nothing.
  if (!seenFromInside) {
    const answering = scan.coverage?.ports_open ?? scan.open_ports?.length ?? 0
    return {
      headline: answering
        ? `${count(answering)} service${answering === 1 ? '' : 's'} answer${answering === 1 ? 's' : ''}, and that is all we know.`
        : 'Nothing answers, and that is all we know.',
      lead: 'This view stops at the door. Launch with attacklens start to see where each one leads.',
    }
  }

  const chains = paths?.paths ?? []
  const confirmed = chains.filter((path) => path.certainty === 'confirmed')
  const proved = exposure?.status === 'verified'

  if (!chains.length) {
    return {
      headline: 'No way in, as far as we can see.',
      lead: proved
        ? 'A probe from another machine agrees.'
        : 'This comes from inside the machine. Only a probe from another one can prove it.',
    }
  }
  if (confirmed.length) {
    return {
      headline: `${count(confirmed.length)} confirmed way${confirmed.length === 1 ? '' : 's'} in.`,
      lead: 'The evidence is there, not just the theory. Start with the first item below.',
    }
  }
  return {
    headline: `${count(chains.length)} way${chains.length === 1 ? '' : 's'} this machine could fall, none proved.`,
    lead: proved
      ? 'A probe from another machine found no entry for now.'
      : 'Your firewall probably stops the network ones, but only a probe from another machine can tell.',
  }
}

export interface Action {
  finding: Finding
  text: string
  reason: string
  breaks: number
}

export const pickActions = (
  network: Finding[],
  host: Finding[],
  paths: AttackPathReport | null,
  limit = 4,
): Action[] => {
  const relevant = [...network, ...host].filter((finding) =>
    isOpen(finding)
    && finding.remediation
    && finding.severity !== 'info'
    && !['software', 'persistence'].includes(finding.category ?? ''),
  )
  // Both views report the same port: keep the one with the most information.
  const unique = new Map<string, Finding>()
  for (const finding of [...relevant].sort(byRisk)) {
    const key = finding.port ? `port-${finding.port}` : finding.finding_id ?? finding.title ?? ''
    if (!unique.has(key)) unique.set(key, finding)
  }

  // What is urgent comes first. After that, the fix closing the most ways in.
  const all = [...unique.values()]
  const cut = paths?.best_cut
  const best = cut ? all.find((finding) => finding.finding_id === cut.finding_id) : undefined
  const urgent = all.filter((finding) => finding.risk?.priority === 'now')
  const ordered = [...new Set([...urgent, ...(best ? [best] : []), ...all])]

  return ordered.slice(0, limit).map((finding) => ({
    finding,
    text: finding.remediation ?? '',
    reason: finding.title ?? '',
    breaks: finding === best ? cut?.paths_broken ?? 0 : 0,
  }))
}
