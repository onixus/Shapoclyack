"use client";

import { useState, useEffect, useRef } from "react";
import {
  Check,
  Copy,
  Cpu,
  Fingerprint,
  Loader2,
  Play,
  KeyRound,
  Server,
  Shield,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  useAgentSnippets,
  useCreateAgentDeploymentKey,
  useDeploySSH,
  useDeployStatus,
  useProbeSSHHostKey,
} from "@/hooks/use-agents";
import { type AgentDeploySSHRequest } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

/** The snippets are rendered with a placeholder until an operator explicitly
 * mints a key — loading this dialog must not create tenant credentials. */
function ProvisioningKeyNotice({
  keyMinted,
  onMint,
  isPending,
  error,
  canMint,
}: {
  keyMinted: boolean;
  onMint: () => void;
  isPending: boolean;
  error: string | null;
  canMint: boolean;
}) {
  if (keyMinted) {
    return (
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-foreground">
        <p className="flex items-center gap-1.5 font-semibold text-amber-600 dark:text-amber-400">
          <KeyRound className="h-3.5 w-3.5" />
          Provisioning key shown once
        </p>
        <p className="mt-1 leading-relaxed text-muted-foreground">
          The key below is embedded in these snippets and cannot be retrieved
          again. Copy the command now; revoke the key from Tenants if it leaks.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-muted/50 p-3 text-xs text-foreground">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 font-semibold">
            <KeyRound className="h-3.5 w-3.5 text-muted-foreground" />
            No provisioning key yet
          </p>
          <p className="mt-1 leading-relaxed text-muted-foreground">
            Snippets show a <code className="font-mono">&lt;PROVISIONING_KEY&gt;</code>{" "}
            placeholder. Generate a key to fill them in — this creates a real
            tenant credential.
          </p>
          {canMint ? null : (
            <p className="mt-1 leading-relaxed text-amber-600 dark:text-amber-400">
              Minting one takes tenant admin: the key registers agents into the
              tenant, the same credential the tenant key administration page
              hands out.
            </p>
          )}
        </div>
        <Button
          size="sm"
          onClick={onMint}
          disabled={isPending || !canMint}
          className="gap-1.5 text-xs"
        >
          {isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <KeyRound className="h-3.5 w-3.5" />}
          Generate key
        </Button>
      </div>
      {error ? <p className="mt-2 text-rose-600 dark:text-rose-400">{error}</p> : null}
    </div>
  );
}

export function DeployAgentDialog() {
  const [open, setOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("ssh");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // SSH Form State
  const [host, setHost] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("root");
  const [authMethod, setAuthMethod] = useState<"password" | "key">("password");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [useDocker, setUseDocker] = useState(false);
  const [expectedHostKey, setExpectedHostKey] = useState("");
  const [activeDeployId, setActiveDeployId] = useState<string | null>(null);

  const deployMutation = useDeploySSH();
  const hostKeyMutation = useProbeSSHHostKey();
  // Both credential-handing actions in this dialog take tenant admin (#231).
  // Offering them to an operator would only produce a 403 they cannot act on.
  const isAdmin = useAuthStore((state) => state.user?.role === "admin");
  const { data: deployStatus } = useDeployStatus(activeDeployId);
  const { data: snippets } = useAgentSnippets();
  const mintKeyMutation = useCreateAgentDeploymentKey();

  const keyNotice = (
    <ProvisioningKeyNotice
      keyMinted={Boolean(snippets?.key_minted)}
      onMint={() => mintKeyMutation.mutate(undefined)}
      isPending={mintKeyMutation.isPending}
      error={mintKeyMutation.error ? (mintKeyMutation.error as Error).message : null}
      canMint={isAdmin}
    />
  );

  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [deployStatus?.logs]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleStartDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!host.trim()) return;

    const payload: AgentDeploySSHRequest = {
      host: host.trim(),
      port: Number(port) || 22,
      username: username.trim() || "root",
      password: authMethod === "password" ? password : undefined,
      private_key: authMethod === "key" ? privateKey : undefined,
      use_docker: useDocker,
      expected_host_key: expectedHostKey.trim() || undefined,
    };

    try {
      const res = await deployMutation.mutateAsync(payload);
      if (res && res.deploy_id) {
        setActiveDeployId(res.deploy_id);
      }
    } catch {
      // A refused host key is the expected first answer for a new target, so
      // the rejection is rendered from deployMutation.error below rather than
      // escaping the submit handler as an unhandled rejection.
    }
  };

  const resetSSHForm = () => {
    setActiveDeployId(null);
    deployMutation.reset();
    hostKeyMutation.reset();
  };

  const probedKey = hostKeyMutation.data;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2 bg-gradient-to-r from-sky-500 to-indigo-600 font-semibold text-white shadow-md shadow-sky-950/20 hover:from-sky-400 hover:to-indigo-500">
          <Server className="h-4 w-4" />
          Deploy Agent
        </Button>
      </DialogTrigger>
      <DialogContent className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden p-0 bg-card text-card-foreground border-border shadow-2xl">
        <DialogHeader className="border-b border-border/80 px-6 pt-6 pb-4">
          <DialogTitle className="flex items-center gap-2.5 text-xl font-bold">
            <Cpu className="h-5 w-5 text-sky-500" />
            Deploy Scanning Agent
          </DialogTitle>
          <DialogDescription className="text-muted-foreground text-xs sm:text-sm">
            Install and register a new security agent to execute remote vulnerability scans.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto custom-scrollbar px-6 py-4">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 gap-1.5 bg-muted/80 p-1 border border-border rounded-lg">
              <TabsTrigger
                value="ssh"
                className="text-xs sm:text-sm font-medium data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-sm"
              >
                Remote SSH Push
              </TabsTrigger>
              <TabsTrigger
                value="systemd"
                className="text-xs sm:text-sm font-medium data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-sm"
              >
                Linux One-Liner
              </TabsTrigger>
              <TabsTrigger
                value="docker"
                className="text-xs sm:text-sm font-medium data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-sm"
              >
                Docker Container
              </TabsTrigger>
              <TabsTrigger
                value="kubernetes"
                className="text-xs sm:text-sm font-medium data-[state=active]:bg-card data-[state=active]:text-foreground data-[state=active]:shadow-sm"
              >
                Kubernetes
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: REMOTE SSH PUSH */}
            <TabsContent value="ssh" className="mt-4 space-y-4">
              {!activeDeployId ? (
                <form onSubmit={handleStartDeploy} className="space-y-4">
                  <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-foreground">
                    <p className="flex items-center gap-1.5 font-semibold text-sky-600 dark:text-sky-400">
                      <Shield className="h-4 w-4" />
                      Agent Push Deployment via SSH
                    </p>
                    <p className="mt-1 text-muted-foreground leading-relaxed">
                      The platform connects to the target machine over SSH, automatically provisions security tokens, configures the systemd service, and verifies registration. Credentials are processed in-memory and never saved.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-2 space-y-1.5">
                      <Label htmlFor="host" className="text-xs font-medium text-foreground">Target Host / IP Address *</Label>
                      <Input
                        id="host"
                        placeholder="192.168.1.100 or scan-node-01.internal"
                        value={host}
                        onChange={(e) => setHost(e.target.value)}
                        required
                        className="font-mono text-sm"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="port" className="text-xs font-medium text-foreground">SSH Port</Label>
                      <Input
                        id="port"
                        type="number"
                        value={port}
                        onChange={(e) => setPort(Number(e.target.value))}
                        className="font-mono text-sm"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label htmlFor="username" className="text-xs font-medium text-foreground">SSH Username</Label>
                      <Input
                        id="username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="font-mono text-sm"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs font-medium text-foreground">Authentication Method</Label>
                      <div className="flex gap-2 pt-1">
                        <Button
                          type="button"
                          size="sm"
                          variant={authMethod === "password" ? "default" : "outline"}
                          onClick={() => setAuthMethod("password")}
                          className="flex-1 text-xs"
                        >
                          Password
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant={authMethod === "key" ? "default" : "outline"}
                          onClick={() => setAuthMethod("key")}
                          className="flex-1 text-xs"
                        >
                          SSH Private Key
                        </Button>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-1.5 rounded-lg border border-border bg-muted/40 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Label htmlFor="host-key" className="text-xs font-medium text-foreground">
                        Expected SSH host key fingerprint
                      </Label>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="gap-1.5 text-xs"
                        disabled={!host.trim() || hostKeyMutation.isPending}
                        onClick={() =>
                          hostKeyMutation.mutate({
                            host: host.trim(),
                            port: Number(port) || 22,
                          })
                        }
                      >
                        {hostKeyMutation.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Fingerprint className="h-3.5 w-3.5" />
                        )}
                        Read from host
                      </Button>
                    </div>
                    <Input
                      id="host-key"
                      placeholder="SHA256:..."
                      value={expectedHostKey}
                      onChange={(e) => setExpectedHostKey(e.target.value)}
                      className="font-mono text-xs"
                    />
                    {probedKey ? (
                      <div className="space-y-1.5 text-xs">
                        <p className="font-mono break-all text-foreground">
                          {probedKey.key_type} {probedKey.fingerprint}
                        </p>
                        {probedKey.pinned ? (
                          <p className="text-muted-foreground">
                            Already pinned for this tenant — no fingerprint needed.
                          </p>
                        ) : (
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-amber-600 dark:text-amber-400">
                              Whoever answered offered this. Confirm it on the host with{" "}
                              <code className="font-mono">
                                ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
                              </code>{" "}
                              before accepting.
                            </p>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              className="text-xs"
                              onClick={() => setExpectedHostKey(probedKey.fingerprint)}
                            >
                              It matches — use it
                            </Button>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        Required the first time this tenant deploys to a host. Your SSH
                        credentials and a new provisioning key travel over this
                        connection, so the deployment is refused until the target&apos;s
                        identity is known. Afterwards the pinned key is checked instead.
                      </p>
                    )}
                    {hostKeyMutation.error ? (
                      <p className="text-xs text-rose-600 dark:text-rose-400">
                        {(hostKeyMutation.error as Error).message}
                      </p>
                    ) : null}
                  </div>

                  {authMethod === "password" ? (
                    <div className="space-y-1.5">
                      <Label htmlFor="ssh-pass" className="text-xs font-medium text-foreground">SSH Password</Label>
                      <Input
                        id="ssh-pass"
                        type="password"
                        placeholder="••••••••••••"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="font-mono text-sm"
                      />
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <Label htmlFor="ssh-key" className="text-xs font-medium text-foreground">OpenSSH / RSA / Ed25519 Private Key</Label>
                      <Textarea
                        id="ssh-key"
                        rows={4}
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                        value={privateKey}
                        onChange={(e) => setPrivateKey(e.target.value)}
                        className="font-mono text-xs"
                      />
                    </div>
                  )}

                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                    <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={useDocker}
                        onChange={(e) => setUseDocker(e.target.checked)}
                        className="rounded border-input bg-background text-primary"
                      />
                      Deploy as Docker container instead of native systemd service
                    </label>

                    <Button
                      type="submit"
                      disabled={deployMutation.isPending || !host || !isAdmin}
                      className="gap-2 font-semibold"
                    >
                      {deployMutation.isPending ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      Start Installation
                    </Button>
                    {isAdmin ? null : (
                      <p className="text-xs text-amber-600 dark:text-amber-400">
                        The push takes tenant admin: it mints a provisioning key
                        and installs software as root on the target.
                      </p>
                    )}
                    {deployMutation.error ? (
                      <p className="text-xs text-rose-600 dark:text-rose-400">
                        {(deployMutation.error as Error).message}
                      </p>
                    ) : null}
                  </div>
                </form>
              ) : (
                /* LIVE DEPLOYMENT STATUS CONSOLE */
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-lg border border-border bg-muted/50 p-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-sky-600 dark:text-sky-400">
                          {deployStatus?.stage || "Processing..."}
                        </span>
                        {deployStatus?.status === "installing" || deployStatus?.status === "connecting" || deployStatus?.status === "verifying" ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-500" />
                        ) : deployStatus?.status === "completed" ? (
                          <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-600 dark:text-emerald-400">
                            SUCCESS
                          </span>
                        ) : deployStatus?.status === "failed" ? (
                          <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-600 dark:text-rose-400">
                            FAILED
                          </span>
                        ) : null}
                      </div>
                      <p className="text-[11px] text-muted-foreground mt-0.5">Target: {host}:{port}</p>
                    </div>

                    <Button
                      size="sm"
                      variant="outline"
                      onClick={resetSSHForm}
                      className="text-xs"
                    >
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                      New Deploy
                    </Button>
                  </div>

                  {/* Progress Bar */}
                  <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                    <div
                      className="h-full bg-gradient-to-r from-sky-500 to-emerald-500 transition-all duration-300"
                      style={{ width: `${deployStatus?.progress_percent ?? 10}%` }}
                    />
                  </div>

                  {/* Log Console */}
                  <div className="terminal-console h-64 overflow-y-auto custom-scrollbar rounded-lg border border-slate-800 p-3.5 font-mono text-xs">
                    <div className="space-y-1">
                      {deployStatus?.logs?.map((line, idx) => (
                        <div
                          key={idx}
                          className={
                            line.includes("[ERROR]") || line.includes("[FATAL]")
                              ? "log-error"
                              : line.includes("[WARN]")
                              ? "log-warn"
                              : line.includes("ONLINE")
                              ? "log-success"
                              : "log-info"
                          }
                        >
                          {line}
                        </div>
                      ))}
                      <div ref={terminalEndRef} />
                    </div>
                  </div>
                </div>
              )}
            </TabsContent>

            {/* TAB 2: LINUX ONE-LINER */}
            <TabsContent value="systemd" className="mt-4 space-y-4">
              {keyNotice}
              <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-foreground">
                <p className="font-semibold text-sky-600 dark:text-sky-400">Automated Systemd Service One-Liner</p>
                <p className="mt-1 text-muted-foreground leading-relaxed">
                  Run this command on any Linux machine (Ubuntu/Debian/RHEL/Alpine). It automatically sets up Python virtualenv, installs dependencies, writes systemd unit, and enables auto-start on boot.
                </p>
              </div>

              <div className="rounded-lg border border-border overflow-hidden bg-slate-950 dark:bg-black shadow-inner">
                <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/90 text-xs text-slate-300">
                  <span className="font-mono text-xs font-semibold text-slate-300">Bash Command</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleCopy(snippets?.systemd_oneliner || "", "systemd")}
                    className="h-7 border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                  >
                    {copiedKey === "systemd" ? (
                      <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="mr-1.5 h-3.5 w-3.5" />
                    )}
                    {copiedKey === "systemd" ? "Copied!" : "Copy"}
                  </Button>
                </div>
                <pre className="p-4 font-mono text-xs text-sky-300 overflow-x-auto custom-scrollbar whitespace-pre">
                  {snippets?.systemd_oneliner || "curl -sSL https://.../api/agent/install.sh | sudo bash"}
                </pre>
              </div>
            </TabsContent>

            {/* TAB 3: DOCKER CONTAINER */}
            <TabsContent value="docker" className="mt-4 space-y-4">
              {keyNotice}
              <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-foreground">
                <p className="font-semibold text-sky-600 dark:text-sky-400">Docker Run Command & Compose</p>
                <p className="mt-1 text-muted-foreground leading-relaxed">
                  Runs the scanning agent in an isolated container with host network access for direct vulnerability scanning.
                </p>
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-border overflow-hidden bg-slate-950 dark:bg-black shadow-inner">
                  <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/90 text-xs text-slate-300">
                    <span className="font-mono text-xs font-semibold text-slate-300">Docker CLI Command</span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleCopy(snippets?.docker_run || "", "docker")}
                      className="h-7 border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                    >
                      {copiedKey === "docker" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                      {copiedKey === "docker" ? "Copied!" : "Copy"}
                    </Button>
                  </div>
                  <pre className="p-4 font-mono text-xs text-sky-300 overflow-x-auto custom-scrollbar whitespace-pre">
                    {snippets?.docker_run || "docker run -d ..."}
                  </pre>
                </div>

                <div className="rounded-lg border border-border overflow-hidden bg-slate-950 dark:bg-black shadow-inner">
                  <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/90 text-xs text-slate-300">
                    <span className="font-mono text-xs font-semibold text-slate-300">docker-compose.yml</span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleCopy(snippets?.docker_compose || "", "compose")}
                      className="h-7 border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                    >
                      {copiedKey === "compose" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                      {copiedKey === "compose" ? "Copied!" : "Copy"}
                    </Button>
                  </div>
                  <pre className="p-4 font-mono text-xs text-slate-200 overflow-x-auto custom-scrollbar whitespace-pre">
                    {snippets?.docker_compose || "version: '3.8'..."}
                  </pre>
                </div>
              </div>
            </TabsContent>

            {/* TAB 4: KUBERNETES */}
            <TabsContent value="kubernetes" className="mt-4 space-y-4">
              {keyNotice}
              <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-foreground">
                <p className="font-semibold text-sky-600 dark:text-sky-400">Kubernetes Deployment Manifest</p>
                <p className="mt-1 text-muted-foreground leading-relaxed">
                  Deploy continuous scanner agents into your Kubernetes cluster to assess internal services.
                </p>
              </div>

              <div className="rounded-lg border border-border overflow-hidden bg-slate-950 dark:bg-black shadow-inner">
                <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/90 text-xs text-slate-300">
                  <span className="font-mono text-xs font-semibold text-slate-300">kubernetes.yaml</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleCopy(snippets?.kubernetes_yaml || "", "k8s")}
                    className="h-7 border-slate-700 bg-slate-800 text-xs text-slate-200 hover:bg-slate-700"
                  >
                    {copiedKey === "k8s" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                    {copiedKey === "k8s" ? "Copied!" : "Copy"}
                  </Button>
                </div>
                <pre className="p-4 font-mono text-xs text-slate-200 max-h-64 overflow-y-auto custom-scrollbar whitespace-pre">
                  {snippets?.kubernetes_yaml || "apiVersion: apps/v1..."}
                </pre>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </DialogContent>
    </Dialog>
  );
}
