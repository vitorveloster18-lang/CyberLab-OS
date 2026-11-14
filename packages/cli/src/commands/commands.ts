import { Argument, Flag, GlobalFlag } from "effect/cli"
import { Schema } from "effect"
import { Spec } from "../framework/spec"
import { Updater } from "../services/updater"

export const PrintLogs = GlobalFlag.Setting("print-logs")({
  flag: Flag.Boolean("print-logs").pipe(
    Flag.withDescription("Print logs to stderr (server logs require --standalone)"),
    Flag.withDefault(false),
  ),
})

export const Standalone = GlobalFlag.Setting("standalone")({
  flag: Flag.Boolean("standalone").pipe(
    Flag.withDescription("Run with a private server instead of the background service"),
    Flag.withDefault(false),
  ),
})

export const Server = GlobalFlag.Setting("server")({
  flag: Flag.String("server").pipe(
    Flag.withDescription("Connect to a server URL instead of the background service"),
    Flag.optional,
  ),
})

const ServerFlags = [Standalone, Server] as const

declare const OPENCODE_CLI_NAME: string | undefined

const ServerParams = {
  standalone: Standalone.flag,
  server: Server.flag,
}

const PermissionParams = {
  auto: Flag.Boolean("auto").pipe(
    Flag.withDescription("Auto-approve permissions that are not explicitly denied"),
    Flag.withDefault(false),
  ),
  yolo: Flag.Boolean("yolo").pipe(Flag.withDefault(false), Flag.withHidden),
  dangerouslySkipPermissions: Flag.Boolean("dangerously-skip-permissions").pipe(
    Flag.withDefault(false),
    Flag.withHidden,
  ),
}

const Root = Spec.make(typeof OPENCODE_CLI_NAME === "string" ? OPENCODE_CLI_NAME : "opencode", {
  description: "OpenCode command line interface",
  params: {
    ...ServerParams,
    ...PermissionParams,
    directory: Argument.String("directory").pipe(
      Argument.withDescription("Directory to start OpenCode in"),
      Argument.optional,
    ),
    continue: Flag.Boolean("continue").pipe(
      Flag.withAlias("c"),
      Flag.withDescription("Continue the last session"),
      Flag.withDefault(false),
    ),
    session: Flag.String("session").pipe(
      Flag.withAlias("s"),
      Flag.withDescription("Session ID to continue, or to create if it does not exist"),
      Flag.optional,
    ),
    prompt: Flag.String("prompt").pipe(Flag.withDescription("Prompt to use"), Flag.optional),
  },
  commands: [
    Spec.make("upgrade", {
      description: "Upgrade OpenCode to the latest or a specific version",
      aliases: ["update"],
      params: {
        target: Argument.String("target").pipe(
          Argument.withDescription("Version to upgrade to (with or without a leading v)"),
          Argument.optional,
        ),
        method: Flag.Literals("method", Updater.methods).pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Installation method to use"),
          Flag.optional,
        ),
      },
    }),
    Spec.make("uninstall", {
      description: "Uninstall OpenCode, keeping session data, configuration, and state",
      params: {
        dryRun: Flag.Boolean("dry-run").pipe(
          Flag.withDescription("Show what would be removed without removing"),
          Flag.withDefault(false),
        ),
        force: Flag.Boolean("force").pipe(
          Flag.withAlias("f"),
          Flag.withDescription("Skip confirmation prompts"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("acp", {
      description: "Start an Agent Client Protocol server",
      params: {
        login: Flag.Boolean("login").pipe(
          Flag.withDescription("Run auth login instead of starting the server"),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("api", {
      description: "Make a request to the running server",
      globalFlags: ServerFlags,
      params: {
        request: Argument.String("operation | method path").pipe(
          Argument.withDescription("OpenAPI operation ID, or an HTTP method followed by a path"),
          Argument.variadic({ min: 1, max: 2 }),
        ),
        data: Flag.String("data").pipe(Flag.withAlias("d"), Flag.withDescription("Request body"), Flag.optional),
        header: Flag.String("header").pipe(
          Flag.withAlias("H"),
          Flag.withDescription("Request header in name:value form"),
          Flag.atMost(100),
        ),
        param: Flag.KeyValuePair("param").pipe(Flag.withDescription("OpenAPI path or query parameter"), Flag.optional),
      },
    }),
    Spec.make("debug", {
      description: "Debugging and troubleshooting tools",
      commands: [
        Spec.make("agents", { description: "List all agents", globalFlags: ServerFlags }),
        Spec.make("config", { description: "List configuration sources", globalFlags: ServerFlags }),
        Spec.make("heap-dump", {
          description: "Write a heap snapshot of the running server and print its path",
          globalFlags: [Server],
          params: {
            directory: Flag.String("directory").pipe(
              Flag.withDescription("Directory to write the snapshot into instead of the server's log directory"),
              Flag.optional,
            ),
          },
        }),
        Spec.make("paths", {
          description: "Show global paths (data, config, cache, state)",
          params: {
            name: Argument.Literals("name", [
              "db",
              "home",
              "data",
              "config",
              "cache",
              "state",
              "tmp",
              "bin",
              "log",
              "repos",
            ]).pipe(
              Argument.withDescription(
                "Print only one path: db, home, data, config, cache, state, tmp, bin, log, repos",
              ),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("auth", {
      description: "manage integrations and credentials",
      globalFlags: ServerFlags,
      commands: [
        Spec.make("list", {
          description: "list integrations and credentials",
          params: {
            format: Flag.Literals("format", ["default", "json"]).pipe(
              Flag.withDescription("Output format"),
              Flag.withDefault("default"),
            ),
          },
        }),
        Spec.make("login", {
          description: "connect an integration",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID, name, or well-known provider URL"),
              Argument.optional,
            ),
            method: Flag.String("method").pipe(Flag.withDescription("Authentication method ID"), Flag.optional),
            answer: Flag.String("answer").pipe(
              Flag.withDescription("Provider form answer (key=value; repeat for multiple fields)"),
              Flag.atMost(100),
            ),
          },
        }),
        Spec.make("logout", {
          description: "log out of a saved account",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name"),
              Argument.optional,
            ),
            credential: Argument.String("credential").pipe(
              Argument.withDescription("Credential ID or label (opens an account picker when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("export", {
          description: "print stored credentials, including secrets, as JSON",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name (exports every integration when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("import", {
          description: "import credentials exported by auth export",
          params: {
            file: Argument.String("file").pipe(
              Argument.withDescription("JSON file to import (reads stdin when omitted)"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("switch", {
          description: "switch the active account for an integration",
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Integration ID or name"),
              Argument.optional,
            ),
            credential: Argument.String("credential").pipe(
              Argument.withDescription("Credential ID or label (opens an account picker when omitted)"),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("mcp", {
      description: "Manage MCP (Model Context Protocol) servers",
      commands: [
        Spec.make("list", {
          description: "List configured MCP servers and their status",
          globalFlags: ServerFlags,
        }),
        Spec.make("add", {
          description: "Add an MCP server to your configuration",
          params: {
            name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server")),
            command: Argument.String("command").pipe(
              Argument.withDescription("Command and arguments for a local server, passed after --"),
              Argument.variadic({ min: 0 }),
            ),
            url: Flag.String("url").pipe(Flag.withDescription("URL for a remote MCP server"), Flag.optional),
            header: Flag.KeyValuePair("header").pipe(
              Flag.withDescription("HTTP header for a remote server, as name=value"),
              Flag.optional,
            ),
            env: Flag.KeyValuePair("env").pipe(
              Flag.withDescription("Environment variable for a local server, as name=value"),
              Flag.optional,
            ),
            global: Flag.Boolean("global").pipe(
              Flag.withDescription("Write to the global config instead of the project config"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("auth", {
          description: "Authenticate with an OAuth-capable remote MCP server",
          globalFlags: ServerFlags,
          params: {
            name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server"), Argument.optional),
          },
        }),
        Spec.make("logout", {
          description: "Remove stored OAuth credentials for an MCP server",
          globalFlags: ServerFlags,
          params: { name: Argument.String("name").pipe(Argument.withDescription("Name of the MCP server")) },
        }),
      ],
    }),
    Spec.make("plugin", {
      description: "Manage plugins",
      commands: [
        Spec.make("list", {
          description: "List plugins",
          globalFlags: ServerFlags,
          params: {
            builtin: Flag.Boolean("builtin").pipe(
              Flag.withDescription("Include built-in server plugins"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("add", {
          description: "Install a plugin and add it to the global configuration",
          params: {
            package: Argument.String("package").pipe(Argument.withDescription("npm registry or Git package specifier")),
          },
        }),
        Spec.make("check", {
          description: "Check package plugins for updates",
          globalFlags: ServerFlags,
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Configured package target"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("update", {
          description: "Update package plugins",
          globalFlags: ServerFlags,
          params: {
            target: Argument.String("target").pipe(
              Argument.withDescription("Configured package target; omit to update all outdated plugins"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("remove", {
          description: "Remove a plugin from global configuration",
          params: {
            package: Argument.String("package").pipe(Argument.withDescription("configured package specifier")),
          },
        }),
      ],
    }),
    Spec.make("models", {
      description: "List all available models",
      globalFlags: ServerFlags,
    }),
    Spec.make("stats", {
      description: "Show shareable usage statistics",
      globalFlags: ServerFlags,
      params: {
        days: Flag.Int("days").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(0))),
          Flag.withDescription("Show the last N days; 0 means today"),
          Flag.optional,
        ),
        year: Flag.Int("year").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isBetween({ minimum: 1970, maximum: 9_999 }))),
          Flag.withDescription("Show a calendar year"),
          Flag.optional,
        ),
        all: Flag.Boolean("all").pipe(Flag.withDescription("Show lifetime statistics"), Flag.withDefault(false)),
        project: Flag.String("project").pipe(
          Flag.withDescription('Filter by project ID, or use "." for the current project'),
          Flag.optional,
        ),
        models: Flag.Boolean("models").pipe(Flag.withDescription("Show model usage"), Flag.withDefault(false)),
        tools: Flag.Boolean("tools").pipe(Flag.withDescription("Show tool reliability"), Flag.withDefault(false)),
        cost: Flag.Boolean("cost").pipe(Flag.withDescription("Show cost and token details"), Flag.withDefault(false)),
        full: Flag.Boolean("full").pipe(Flag.withDescription("Show every detailed section"), Flag.withDefault(false)),
        limit: Flag.Int("limit").pipe(
          Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))),
          Flag.withDescription("Number of rows in detailed sections"),
          Flag.withDefault(5),
        ),
        json: Flag.Boolean("json").pipe(Flag.withDescription("Output statistics as JSON"), Flag.withDefault(false)),
      },
    }),
    Spec.make("mini", {
      description: "Start the minimal interactive interface",
      globalFlags: ServerFlags,
      params: {
        continue: Flag.Boolean("continue").pipe(
          Flag.withAlias("c"),
          Flag.withDescription("Continue the last session"),
          Flag.withDefault(false),
        ),
        session: Flag.String("session").pipe(
          Flag.withAlias("s"),
          Flag.withDescription("Session ID to continue, or to create if it does not exist"),
          Flag.optional,
        ),
        fork: Flag.Boolean("fork").pipe(
          Flag.withDescription("Fork the session when continuing"),
          Flag.withDefault(false),
        ),
        replay: Flag.Boolean("replay").pipe(
          Flag.withDescription("Restore session history on resume and resize (disable with --no-replay)"),
          Flag.optional,
        ),
        replayLimit: Flag.Int("replay-limit").pipe(
          Flag.withDescription("Limit replay to the newest N messages (default: 200)"),
          Flag.optional,
        ),
        model: Flag.String("model").pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Model to use in the format provider/model"),
          Flag.optional,
        ),
        agent: Flag.String("agent").pipe(Flag.withDescription("Agent to use"), Flag.optional),
        prompt: Flag.String("prompt").pipe(Flag.withDescription("Prompt to use"), Flag.optional),
        demo: Flag.Boolean("demo").pipe(Flag.withDefault(false), Flag.withHidden),
      },
    }),
    Spec.make("run", {
      description: "Run OpenCode with a message",
      globalFlags: ServerFlags,
      params: {
        message: Argument.String("message").pipe(
          Argument.withDescription("Message to send"),
          Argument.variadic({ min: 0 }),
        ),
        continue: Flag.Boolean("continue").pipe(
          Flag.withAlias("c"),
          Flag.withDescription("Continue the last session"),
          Flag.withDefault(false),
        ),
        session: Flag.String("session").pipe(
          Flag.withAlias("s"),
          Flag.withDescription("Session ID to continue, or to create if it does not exist"),
          Flag.optional,
        ),
        fork: Flag.Boolean("fork").pipe(
          Flag.withDescription("Fork the session before continuing"),
          Flag.withDefault(false),
        ),
        model: Flag.String("model").pipe(
          Flag.withAlias("m"),
          Flag.withDescription("Model to use in the format provider/model#variant"),
          Flag.optional,
        ),
        agent: Flag.String("agent").pipe(Flag.withDescription("Agent to use"), Flag.optional),
        format: Flag.Literals("format", ["default", "json"]).pipe(
          Flag.withDescription("Output format"),
          Flag.withDefault("default"),
        ),
        file: Flag.String("file").pipe(
          Flag.withAlias("f"),
          Flag.withDescription("File to attach to the message"),
          Flag.atMost(100),
        ),
        title: Flag.String("title").pipe(Flag.withDescription("Session title"), Flag.optional),
        thinking: Flag.Boolean("thinking").pipe(Flag.withDescription("Show thinking blocks"), Flag.withDefault(false)),
        ...PermissionParams,
      },
    }),
    Spec.make("session", {
      description: "Manage sessions",
      globalFlags: ServerFlags,
      commands: [
        Spec.make("list", {
          description: "List top-level sessions in the current project, newest first",
          params: {
            maxCount: Flag.Int("max-count").pipe(
              Flag.withAlias("n"),
              Flag.withSchema(Schema.Int.check(Schema.isGreaterThanOrEqualTo(1))),
              Flag.withDescription("Limit to N most recent sessions (default: 100)"),
              Flag.optional,
            ),
            format: Flag.Literals("format", ["table", "json"]).pipe(
              Flag.withDescription("Output format"),
              Flag.withDefault("table"),
            ),
          },
        }),
        Spec.make("delete", {
          description: "Delete a session and its child sessions",
          params: {
            sessionID: Argument.String("sessionID").pipe(Argument.withDescription("Session ID to delete")),
          },
        }),
        Spec.make("export", {
          description: "Export session data as JSON",
          params: {
            session: Argument.String("session").pipe(
              Argument.withDescription("Session ID to export"),
              Argument.optional,
            ),
            sanitize: Flag.Boolean("sanitize").pipe(
              Flag.withDescription("Redact sensitive transcript and file data"),
              Flag.withDefault(false),
            ),
          },
        }),
        Spec.make("import", {
          description: "Import session data from a JSON file or URL",
          params: {
            file: Argument.String("file").pipe(Argument.withDescription("JSON file or URL to import")),
            directory: Flag.String("directory").pipe(
              Flag.withDescription("Directory in which to import the session"),
              Flag.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("service", {
      description: "Manage the background server",
      commands: [
        Spec.make("start", { description: "Start the background server" }),
        Spec.make("restart", { description: "Restart the background server" }),
        Spec.make("status", { description: "Show background server status" }),
        Spec.make("stop", { description: "Stop the background server" }),
        Spec.make("get", {
          description: "Get service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env"), Argument.optional),
            name: Argument.String("name").pipe(
              Argument.withDescription("Environment variable name"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("set", {
          description: "Set service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env")),
            value: Argument.String("value").pipe(
              Argument.withDescription("Setting value or environment variable name"),
            ),
            nestedValue: Argument.String("env-value").pipe(
              Argument.withDescription("Environment variable value"),
              Argument.optional,
            ),
          },
        }),
        Spec.make("unset", {
          description: "Unset service configuration",
          params: {
            key: Argument.String("key").pipe(Argument.withDescription("Service setting or env")),
            name: Argument.String("name").pipe(
              Argument.withDescription("Environment variable name"),
              Argument.optional,
            ),
          },
        }),
      ],
    }),
    Spec.make("reload", {
      description: "Reload configuration",
      globalFlags: ServerFlags,
    }),
    Spec.make("pair", {
      description: "Print one-time links to connect a browser or app",
      params: {
        url: Flag.String("url").pipe(
          Flag.withDescription("Use an external HTTP(S) server URL in pairing links"),
          Flag.mapTryCatch(
            (value) => {
              const url = new URL(value)
              if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash)
                throw new Error("Invalid pairing URL")
              return url.href.replace(/\/+$/, "")
            },
            () => "Expected an HTTP(S) server URL without credentials, query parameters, or a fragment",
          ),
          Flag.optional,
        ),
        remote: Flag.Boolean("remote").pipe(
          Flag.withDescription(
            "Pair through the OpenTunnel remote address, enabling remote access if needed (exposes the server to the internet)",
          ),
          Flag.withDefault(false),
        ),
        yes: Flag.Boolean("yes").pipe(
          Flag.withAlias("y"),
          Flag.withDescription(
            "Accept exposing the server to the internet when --remote enables remote access for the first time (required without an interactive terminal)",
          ),
          Flag.withDefault(false),
        ),
      },
    }),
    Spec.make("serve", {
      description: "Start the v2 API and web server",
      params: {
        hostname: Flag.String("hostname").pipe(Flag.optional),
        port: Flag.Int("port").pipe(Flag.optional),
        cors: Flag.String("cors").pipe(
          Flag.withSchema(Schema.NonEmptyString),
          Flag.withDescription("Additional allowed CORS origin (repeat for multiple origins)"),
          Flag.atLeast(0),
        ),
        service: Flag.Boolean("service").pipe(Flag.withDefault(false)),
        stdio: Flag.Boolean("stdio").pipe(Flag.withDefault(false)),
      },
    }),
    Spec.make("cyberlab", {
      description: "Manage CyberLab OS security workspace, scope, executions, and SHA-256 evidence",
      commands: [
        Spec.make("status", {
          description: "Show unified CyberLab workspace status and scope summary",
          params: {
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output status as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("capabilities", {
          description: "List registered local CyberLab capabilities and risk levels",
          params: {
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output capabilities as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("run", {
          description: "Submit a structured capability execution in the CyberLab workspace",
          params: {
            capability: Flag.String("capability").pipe(
              Flag.withAlias("c"),
              Flag.withDescription("Capability ID (e.g. code-analysis.workspace-audit)"),
            ),
            input: Flag.String("input").pipe(
              Flag.withAlias("i"),
              Flag.withDescription("JSON-encoded structured input parameters"),
              Flag.withDefault("{}"),
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output execution record as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("exec", {
          description:
            "Run a native command under CyberLab scope guard, secret redaction and SHA-256 evidence capture",
          params: {
            command: Argument.String("command").pipe(
              Argument.withDescription("Command and arguments, passed after -- (e.g. nmap -sV 10.0.0.5)"),
              Argument.variadic({ min: 0 }),
            ),
            timeout: Flag.String("timeout").pipe(
              Flag.withDescription("Timeout in seconds (default 1800)"),
              Flag.optional,
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("scope", {
          description:
            "Show, set or clear the authorized engagement scope used by `cyberlab exec`",
          params: {
            targets: Argument.String("targets").pipe(
              Argument.withDescription("Allowed targets (e.g. 10.0.0.0/24 exemplo.com)"),
              Argument.variadic({ min: 0 }),
            ),
            clear: Flag.Boolean("clear").pipe(
              Flag.withDescription("Deactivate the scope (cyberlab exec then refuses network targets)"),
              Flag.withDefault(false),
            ),
            external: Flag.Boolean("external").pipe(
              Flag.withDescription("Allow public/routable external targets when setting a scope"),
              Flag.withDefault(false),
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("evidence", {
          description: "List or verify SHA-256 evidence records in the CyberLab workspace",
          params: {
            verify: Flag.String("verify").pipe(
              Flag.withDescription("Evidence ID to verify SHA-256 custody integrity"),
              Flag.optional,
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("findings", {
          description: "List CyberLab security findings and review statuses",
          params: {
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output findings as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("report", {
          description: "Render a reproducible Markdown assessment report for the workspace",
        }),
        Spec.make("partner", {
          description:
            "Configure CDI partner agents (Kairos, Naia, Salem, Nova, etc.), manage CYBERLAB_PARTNER_SECRET, or dispatch tasks (single or parallel)",
          params: {
            objective: Flag.String("objective").pipe(
              Flag.withAlias("o"),
              Flag.withDescription("Task objective sent to the CDI agent(s)"),
              Flag.optional,
            ),
            partnerId: Flag.String("partner-id").pipe(
              Flag.withDescription("Single CDI partner ID (e.g. salem)"),
              Flag.optional,
            ),
            partners: Flag.String("partners").pipe(
              Flag.withDescription("Comma-separated CDI IDs for parallel collaboration (e.g. salem,kairos,naia or *)"),
              Flag.optional,
            ),
            endpoint: Flag.String("endpoint").pipe(
              Flag.withDescription("Partner HTTP endpoint override"),
              Flag.optional,
            ),
            evidence: Flag.String("evidence").pipe(
              Flag.withAlias("e"),
              Flag.withDescription("Comma-separated Evidence IDs to redact and attach"),
              Flag.optional,
            ),
            list: Flag.Boolean("list").pipe(
              Flag.withDescription("List registered CDI partners, callback URL, and secret preview"),
              Flag.withDefault(false),
            ),
            preset4: Flag.Boolean("preset-4").pipe(
              Flag.withDescription("Register the 4 default CDI agents on ports 8788-8791 (kairos, naia, salem, nova)"),
              Flag.withDefault(false),
            ),
            generateSecret: Flag.Boolean("generate-secret").pipe(
              Flag.withDescription("Generate and save a new 64-char HMAC secret in .cyberlab/partners.json"),
              Flag.withDefault(false),
            ),
            setSecret: Flag.String("set-secret").pipe(
              Flag.withDescription("Save a custom CYBERLAB_PARTNER_SECRET (>= 16 chars) in .cyberlab/partners.json"),
              Flag.optional,
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output full outcome as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("external", {
          description:
            "Unified Control Plane for external tools (nmap, nuclei, ffuf, tshark, opentrap, mvt, ghidra), manual ingest, and .cyberlab/inbox sync",
          params: {
            action: Flag.String("action").pipe(
              Flag.withAlias("a"),
              Flag.withDescription("Operation: tools | sync | ingest | wrap (defaults to tools)"),
              Flag.optional,
            ),
            tool: Flag.String("tool").pipe(
              Flag.withDescription("External tool identifier (e.g. opentrap, nmap, burp, wireshark, nuclei)"),
              Flag.optional,
            ),
            target: Flag.String("target").pipe(
              Flag.withAlias("t"),
              Flag.withDescription("Target host, URL, IP, or workspace path for ScopeController audit"),
              Flag.optional,
            ),
            file: Flag.String("file").pipe(
              Flag.withAlias("f"),
              Flag.withDescription("File containing raw output from an external tool run (for --action ingest)"),
              Flag.optional,
            ),
            binary: Flag.String("binary").pipe(
              Flag.withDescription("External binary name or path (for --action wrap)"),
              Flag.optional,
            ),
            args: Flag.String("args").pipe(
              Flag.withDescription("JSON array of CLI arguments passed with shell=false (for --action wrap)"),
              Flag.optional,
            ),
            json: Flag.Boolean("json").pipe(Flag.withDescription("Output as JSON"), Flag.withDefault(false)),
          },
        }),
        Spec.make("studio", {
          description:
            "Launch the full-screen browser Security Studio workbench (Proxy, Repeater, Decoder, Web/Nuclei/ffuf, Nmap/TLS, PCAP, Forensics, Custody)",
          params: {
            port: Flag.Int("port").pipe(
              Flag.withAlias("p"),
              Flag.withDescription("HTTP port to bind (default: 4180)"),
              Flag.optional,
            ),
            host: Flag.String("host").pipe(
              Flag.withDescription("Hostname/interface to bind (default: 0.0.0.0)"),
              Flag.optional,
            ),
            demoLab: Flag.Boolean("demo-lab").pipe(
              Flag.withDescription("Spin up an isolated localhost HTTP/TLS/PCAP/ELF/APK demo lab target"),
              Flag.withDefault(false),
            ),
          },
        }),
      ],
    }),
  ],
})

export const Commands = Root
