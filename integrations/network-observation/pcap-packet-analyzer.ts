import { readFileSync, statSync } from "node:fs"
import path from "node:path"
import { Schema } from "effect"
import {
  isPathInsideRoot,
  normalizeRawOutputDraft,
  type CapabilityDefinition,
  type CyberLabExecutor,
  type ExecutorContext,
  type ExecutorInput,
  type ExecutorResult,
} from "../../cyberlab/index.js"

export const PCAP_ANALYZER_INPUT_SCHEMA_ID = "cyberlab.pcap-analyzer.input.v1"
export const PCAP_ANALYZER_OUTPUT_SCHEMA_ID = "cyberlab.pcap-analyzer.output.v1"

export const PcapAnalyzerInputSchema = Schema.Struct({
  pcapPath: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512)),
  maxPackets: Schema.optionalKey(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(50_000))),
})

export type PcapAnalyzerInput = typeof PcapAnalyzerInputSchema.Type

export const PcapAnalyzerCapability: CapabilityDefinition = {
  id: "network-assessment.pcap-analyzer",
  version: "1.0.0",
  title: "Native Pure-TypeScript .pcap Packet Capture Analyzer (Wireshark/tshark Alternative)",
  description:
    "Parses standard libpcap (.pcap) packet captures inside the workspace without external GPL dependencies, extracting IPv4/IPv6 flows, TCP/UDP port conversations, DNS query domains, cleartext HTTP requests, and TLS ClientHello SNI hostnames.",
  inputSchemaId: PCAP_ANALYZER_INPUT_SCHEMA_ID,
  outputSchemaId: PCAP_ANALYZER_OUTPUT_SCHEMA_ID,
  risk: "read_only",
  supportedModes: ["manual", "proposed", "approved", "lab_automation"],
  requiredPermissions: ["cyberlab:read"],
  requiredScope: ["workspace_path"],
  executorId: "pcap-packet-analyzer-executor",
  skillIds: ["network-assessment", "evidence-review"],
  licenseRefs: ["MIT"],
  enabled: true,
}

function parseDnsQueryName(dnsPayload: Uint8Array): string | null {
  // DNS header is 12 bytes; QDCOUNT at bytes 4..5
  if (dnsPayload.byteLength < 17) return null
  const qdCount = ((dnsPayload[4] ?? 0) << 8) | (dnsPayload[5] ?? 0)
  if (qdCount === 0 || qdCount > 16) return null
  const labels: string[] = []
  let offset = 12
  while (offset < dnsPayload.byteLength) {
    const len = dnsPayload[offset] ?? 0
    if (len === 0) {
      return labels.length > 0 ? labels.join(".") : null
    }
    // Compression pointer or invalid label length in first question
    if (len >= 64 || offset + 1 + len > dnsPayload.byteLength) return null
    const labelBytes = dnsPayload.subarray(offset + 1, offset + 1 + len)
    const label = new TextDecoder("ascii", { fatal: false }).decode(labelBytes)
    if (!/^[a-zA-Z0-9_-]+$/.test(label)) return null
    labels.push(label)
    offset += 1 + len
  }
  return null
}

function parseTlsClientHelloSni(tcpPayload: Uint8Array): string | null {
  // TLS record type 0x16 (Handshake), Handshake type 0x01 (ClientHello)
  if (tcpPayload.byteLength < 43 || tcpPayload[0] !== 0x16 || tcpPayload[5] !== 0x01) return null
  try {
    let pos = 5 + 4 + 2 + 32 // record hdr (5) + handshake hdr (4) + client_version (2) + random (32)
    if (pos >= tcpPayload.byteLength) return null
    const sessionIdLen = tcpPayload[pos] ?? 0
    pos += 1 + sessionIdLen
    if (pos + 2 > tcpPayload.byteLength) return null
    const cipherSuitesLen = ((tcpPayload[pos] ?? 0) << 8) | (tcpPayload[pos + 1] ?? 0)
    pos += 2 + cipherSuitesLen
    if (pos + 1 > tcpPayload.byteLength) return null
    const compMethodsLen = tcpPayload[pos] ?? 0
    pos += 1 + compMethodsLen
    if (pos + 2 > tcpPayload.byteLength) return null
    const extensionsLen = ((tcpPayload[pos] ?? 0) << 8) | (tcpPayload[pos + 1] ?? 0)
    pos += 2
    const endExt = Math.min(tcpPayload.byteLength, pos + extensionsLen)

    while (pos + 4 <= endExt) {
      const extType = ((tcpPayload[pos] ?? 0) << 8) | (tcpPayload[pos + 1] ?? 0)
      const extLen = ((tcpPayload[pos + 2] ?? 0) << 8) | (tcpPayload[pos + 3] ?? 0)
      pos += 4
      if (extType === 0x0000 && pos + 5 <= endExt) {
        // server_name extension: listLen(2), nameType(1 == host_name), nameLen(2)
        const nameType = tcpPayload[pos + 2] ?? 1
        const nameLen = ((tcpPayload[pos + 3] ?? 0) << 8) | (tcpPayload[pos + 4] ?? 0)
        if (nameType === 0 && pos + 5 + nameLen <= endExt) {
          return new TextDecoder("ascii", { fatal: false }).decode(tcpPayload.subarray(pos + 5, pos + 5 + nameLen))
        }
      }
      pos += extLen
    }
  } catch {
    return null
  }
  return null
}

export class PcapPacketAnalyzerExecutor implements CyberLabExecutor {
  readonly id = "pcap-packet-analyzer-executor"
  readonly version = "1.0.0"

  async checkAvailability(): Promise<{ available: boolean; version?: string }> {
    return { available: true, version: this.version }
  }

  async validate(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const decoded = Schema.decodeUnknownSync(PcapAnalyzerInputSchema)(input)
      if (decoded.pcapPath.includes("\0")) return { valid: false, errors: ["Null byte in pcapPath"] }
      return { valid: true, errors: [] }
    } catch (err) {
      return { valid: false, errors: [err instanceof Error ? err.message : String(err)] }
    }
  }

  async execute(execInput: ExecutorInput, ctx: ExecutorContext): Promise<ExecutorResult> {
    const params = Schema.decodeUnknownSync(PcapAnalyzerInputSchema)(execInput.input)
    if (!isPathInsideRoot(params.pcapPath, ctx.workspaceRoot)) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `pcapPath "${params.pcapPath}" escapes workspaceRoot`,
        exitCode: 2,
      }
    }

    const fullPath = path.resolve(ctx.workspaceRoot, params.pcapPath)
    const st = statSync(fullPath, { throwIfNoEntry: false })
    if (!st || !st.isFile()) {
      return { status: "failed", evidenceIds: [], summary: `PCAP file not found: ${params.pcapPath}`, exitCode: 2 }
    }
    if (st.size < 24 || st.size > 64 * 1024 * 1024) {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `PCAP file size (${st.size} bytes) must be between 24 bytes and 64 MiB`,
        exitCode: 2,
      }
    }

    const buf = new Uint8Array(readFileSync(fullPath))
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
    const magicBe = view.getUint32(0, false)

    let littleEndian: boolean
    if (magicBe === 0xd4c3b2a1 || magicBe === 0x4d3cb2a1) {
      littleEndian = true
    } else if (magicBe === 0xa1b2c3d4 || magicBe === 0xa1b23c4d) {
      littleEndian = false
    } else {
      return {
        status: "failed",
        evidenceIds: [],
        summary: `Unsupported capture magic 0x${magicBe.toString(16)} (expected standard .pcap)`,
        exitCode: 2,
      }
    }

    const linkType = view.getUint32(20, littleEndian) // 1 = Ethernet, 101 = Raw IP, 113 = Linux SLL
    const maxPackets = params.maxPackets ?? 10_000

    let offset = 24
    let packetCount = 0
    let totalCapturedBytes = 0
    const protocolCounts: Record<string, number> = { tcp: 0, udp: 0, icmp: 0, other: 0 }
    const flowCounts = new Map<string, number>()
    const dnsQueries = new Set<string>()
    const tlsSniHosts = new Set<string>()
    const httpRequests: string[] = []

    while (offset + 16 <= buf.byteLength && packetCount < maxPackets) {
      if (ctx.signal.aborted) {
        return { status: "cancelled", evidenceIds: [], summary: "Cancelled during PCAP parsing" }
      }
      const inclLen = view.getUint32(offset + 8, littleEndian)
      offset += 16
      if (offset + inclLen > buf.byteLength) break

      const pkt = buf.subarray(offset, offset + inclLen)
      offset += inclLen
      packetCount++
      totalCapturedBytes += inclLen

      let ipOffset = 0
      let etherType = 0x0800
      if (linkType === 1) {
        if (pkt.byteLength < 14) continue
        etherType = ((pkt[12] ?? 0) << 8) | (pkt[13] ?? 0)
        ipOffset = 14
        if (etherType === 0x8100 && pkt.byteLength >= 18) {
          etherType = ((pkt[16] ?? 0) << 8) | (pkt[17] ?? 0)
          ipOffset = 18
        }
      } else if (linkType === 113) {
        if (pkt.byteLength < 16) continue
        etherType = ((pkt[14] ?? 0) << 8) | (pkt[15] ?? 0)
        ipOffset = 16
      } else if (linkType === 101) {
        ipOffset = 0
        const ver = (pkt[0] ?? 0) >> 4
        etherType = ver === 6 ? 0x86dd : 0x0800
      } else {
        continue
      }

      if (etherType !== 0x0800 || pkt.byteLength < ipOffset + 20) continue
      const ipHdr = pkt.subarray(ipOffset)
      const ihl = ((ipHdr[0] ?? 0) & 0x0f) * 4
      if (ihl < 20 || ipHdr.byteLength < ihl) continue

      const proto = ipHdr[9] ?? 0
      const srcIp = `${ipHdr[12]}.${ipHdr[13]}.${ipHdr[14]}.${ipHdr[15]}`
      const dstIp = `${ipHdr[16]}.${ipHdr[17]}.${ipHdr[18]}.${ipHdr[19]}`
      const l4 = ipHdr.subarray(ihl)

      if (proto === 6 && l4.byteLength >= 20) {
        protocolCounts.tcp = (protocolCounts.tcp ?? 0) + 1
        const srcPort = ((l4[0] ?? 0) << 8) | (l4[1] ?? 0)
        const dstPort = ((l4[2] ?? 0) << 8) | (l4[3] ?? 0)
        const dataOffset = (((l4[12] ?? 0) >> 4) & 0x0f) * 4
        const flowKey = `TCP ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`
        flowCounts.set(flowKey, (flowCounts.get(flowKey) ?? 0) + 1)

        if (dataOffset >= 20 && l4.byteLength > dataOffset) {
          const appPayload = l4.subarray(dataOffset)
          const sni = parseTlsClientHelloSni(appPayload)
          if (sni) tlsSniHosts.add(sni)

          const asciiHead = new TextDecoder("ascii", { fatal: false }).decode(appPayload.subarray(0, 160))
          const httpMatch = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\r\n]{1,120})\s+HTTP\/1\.[01]/.exec(
            asciiHead,
          )
          if (httpMatch && httpRequests.length < 50) {
            httpRequests.push(`${srcIp} -> ${dstIp}:${dstPort} ${httpMatch[1]} ${httpMatch[2]}`)
          }
        }
      } else if (proto === 17 && l4.byteLength >= 8) {
        protocolCounts.udp = (protocolCounts.udp ?? 0) + 1
        const srcPort = ((l4[0] ?? 0) << 8) | (l4[1] ?? 0)
        const dstPort = ((l4[2] ?? 0) << 8) | (l4[3] ?? 0)
        const flowKey = `UDP ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`
        flowCounts.set(flowKey, (flowCounts.get(flowKey) ?? 0) + 1)

        if ((srcPort === 53 || dstPort === 53) && l4.byteLength > 8) {
          const qname = parseDnsQueryName(l4.subarray(8))
          if (qname) dnsQueries.add(qname)
        }
      } else if (proto === 1) {
        protocolCounts.icmp = (protocolCounts.icmp ?? 0) + 1
      } else {
        protocolCounts.other = (protocolCounts.other ?? 0) + 1
      }
    }

    const topFlows = [...flowCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 25)
      .map(([flow, packets]) => ({ flow, packets }))

    const summaryReport = {
      pcapPath: params.pcapPath,
      linkType,
      packetCount,
      totalCapturedBytes,
      protocolCounts,
      topFlows,
      dnsQueries: [...dnsQueries],
      tlsSniHosts: [...tlsSniHosts],
      cleartextHttpRequests: httpRequests,
    }

    const evId = await ctx.emitEvidence(
      normalizeRawOutputDraft({
        kind: "network_observation",
        title: `Native PCAP Analysis (${packetCount} packets, ${topFlows.length} flows)`,
        rawText: JSON.stringify(summaryReport, null, 2),
        mediaType: "application/json",
        toolId: "cyberlab-pcap-analyzer",
        toolVersion: this.version,
        executorId: this.id,
        executionId: ctx.executionId,
        maxOutputBytes: 512 * 1024,
        labels: ["pcap", "packet-analysis"],
      }),
    )

    return {
      status: "succeeded",
      evidenceIds: [evId],
      summary: `Parsed ${packetCount} packet(s) from ${params.pcapPath}; DNS=${dnsQueries.size}, TLS_SNI=${tlsSniHosts.size}, HTTP=${httpRequests.length}.`,
      exitCode: 0,
    }
  }
}
