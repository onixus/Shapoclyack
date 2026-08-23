"use client";

import { useState, useEffect, useRef } from "react";
import {
  Check,
  Copy,
  Cpu,
  Loader2,
  Play,
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
import { useDeploySSH, useDeployStatus, useAgentSnippets } from "@/hooks/use-agents";
import { type AgentDeploySSHRequest } from "@/lib/api";

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
  const [activeDeployId, setActiveDeployId] = useState<string | null>(null);

  const deployMutation = useDeploySSH();
  const { data: deployStatus } = useDeployStatus(activeDeployId);
  const { data: snippets } = useAgentSnippets();

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
    };

    const res = await deployMutation.mutateAsync(payload);
    if (res && res.deploy_id) {
      setActiveDeployId(res.deploy_id);
    }
  };

  const resetSSHForm = () => {
    setActiveDeployId(null);
    deployMutation.reset();
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2 bg-gradient-to-r from-sky-500 to-indigo-600 font-semibold text-white shadow-lg shadow-sky-950/50 hover:from-sky-400 hover:to-indigo-500">
          <Server className="h-4 w-4" />
          Deploy Agent
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl border-slate-800 bg-slate-950 text-slate-100 shadow-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2.5 text-xl font-bold">
            <Cpu className="h-5 w-5 text-sky-400" />
            Deploy Scanning Agent
          </DialogTitle>
          <DialogDescription className="text-slate-400">
            Install and register a new security agent to execute remote vulnerability scans.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-2">
          <TabsList className="grid w-full grid-cols-4 border border-slate-800 bg-slate-900/90 p-1">
            <TabsTrigger value="ssh" className="data-[state=active]:bg-sky-500 data-[state=active]:text-white">
              Remote SSH Push
            </TabsTrigger>
            <TabsTrigger value="systemd" className="data-[state=active]:bg-sky-500 data-[state=active]:text-white">
              Linux One-Liner
            </TabsTrigger>
            <TabsTrigger value="docker" className="data-[state=active]:bg-sky-500 data-[state=active]:text-white">
              Docker Container
            </TabsTrigger>
            <TabsTrigger value="kubernetes" className="data-[state=active]:bg-sky-500 data-[state=active]:text-white">
              Kubernetes Manifest
            </TabsTrigger>
          </TabsList>

          {/* TAB 1: REMOTE SSH PUSH */}
          <TabsContent value="ssh" className="mt-4 space-y-4">
            {!activeDeployId ? (
              <form onSubmit={handleStartDeploy} className="space-y-4">
                <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-4 text-xs text-slate-300">
                  <p className="flex items-center gap-1.5 font-medium text-sky-400">
                    <Shield className="h-4 w-4" />
                    Agent Push Deployment via SSH
                  </p>
                  <p className="mt-1 text-slate-400">
                    The platform connects to the target machine over SSH, automatically provisions security tokens, configures the systemd service, and verifies registration. Credentials are processed in-memory and never saved.
                  </p>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2 space-y-1.5">
                    <Label htmlFor="host" className="text-xs text-slate-300">Target Host / IP Address *</Label>
                    <Input
                      id="host"
                      placeholder="192.168.1.100 or scan-node-01.internal"
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      required
                      className="border-slate-800 bg-slate-900 font-mono text-sm text-slate-100"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="port" className="text-xs text-slate-300">SSH Port</Label>
                    <Input
                      id="port"
                      type="number"
                      value={port}
                      onChange={(e) => setPort(Number(e.target.value))}
                      className="border-slate-800 bg-slate-900 font-mono text-sm text-slate-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="username" className="text-xs text-slate-300">SSH Username</Label>
                    <Input
                      id="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="border-slate-800 bg-slate-900 font-mono text-sm text-slate-100"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs text-slate-300">Authentication Method</Label>
                    <div className="flex gap-2 pt-1">
                      <Button
                        type="button"
                        size="sm"
                        variant={authMethod === "password" ? "default" : "outline"}
                        onClick={() => setAuthMethod("password")}
                        className={authMethod === "password" ? "bg-sky-600 text-white" : "border-slate-800 text-slate-400"}
                      >
                        Password
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant={authMethod === "key" ? "default" : "outline"}
                        onClick={() => setAuthMethod("key")}
                        className={authMethod === "key" ? "bg-sky-600 text-white" : "border-slate-800 text-slate-400"}
                      >
                        SSH Private Key
                      </Button>
                    </div>
                  </div>
                </div>

                {authMethod === "password" ? (
                  <div className="space-y-1.5">
                    <Label htmlFor="ssh-pass" className="text-xs text-slate-300">SSH Password</Label>
                    <Input
                      id="ssh-pass"
                      type="password"
                      placeholder="••••••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="border-slate-800 bg-slate-900 font-mono text-sm text-slate-100"
                    />
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <Label htmlFor="ssh-key" className="text-xs text-slate-300">OpenSSH / RSA / Ed25519 Private Key</Label>
                    <Textarea
                      id="ssh-key"
                      rows={4}
                      placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      className="border-slate-800 bg-slate-900 font-mono text-xs text-slate-100"
                    />
                  </div>
                )}

                <div className="flex items-center justify-between pt-2">
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-400">
                    <input
                      type="checkbox"
                      checked={useDocker}
                      onChange={(e) => setUseDocker(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-sky-500"
                    />
                    Deploy as Docker container instead of native systemd service
                  </label>

                  <Button
                    type="submit"
                    disabled={deployMutation.isPending || !host}
                    className="gap-2 bg-sky-600 font-semibold text-white hover:bg-sky-500"
                  >
                    {deployMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}
                    Start Installation
                  </Button>
                </div>
              </form>
            ) : (
              /* LIVE DEPLOYMENT STATUS CONSOLE */
              <div className="space-y-4">
                <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900 p-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-sky-400">
                        {deployStatus?.stage || "Processing..."}
                      </span>
                      {deployStatus?.status === "installing" || deployStatus?.status === "connecting" || deployStatus?.status === "verifying" ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-400" />
                      ) : deployStatus?.status === "completed" ? (
                        <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-400">
                          SUCCESS
                        </span>
                      ) : deployStatus?.status === "failed" ? (
                        <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-400">
                          FAILED
                        </span>
                      ) : null}
                    </div>
                    <p className="text-[11px] text-slate-400">Target: {host}:{port}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={resetSSHForm}
                      className="border-slate-800 text-xs text-slate-300 hover:bg-slate-800"
                    >
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                      New Deploy
                    </Button>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full bg-gradient-to-r from-sky-500 to-emerald-500 transition-all duration-300"
                    style={{ width: `${deployStatus?.progress_percent ?? 10}%` }}
                  />
                </div>

                {/* Log Console */}
                <div className="h-64 overflow-y-auto rounded-lg border border-slate-800 bg-black/90 p-3 font-mono text-[11px] text-slate-300">
                  <div className="space-y-1">
                    {deployStatus?.logs?.map((line, idx) => (
                      <div
                        key={idx}
                        className={
                          line.includes("[ERROR]") || line.includes("[FATAL]")
                            ? "text-rose-400"
                            : line.includes("[WARN]")
                            ? "text-amber-400"
                            : line.includes("ONLINE")
                            ? "text-emerald-400 font-bold"
                            : "text-slate-300"
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
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-4 text-xs text-slate-300">
              <p className="font-medium text-sky-400">Automated Systemd Service One-Liner</p>
              <p className="mt-1 text-slate-400">
                Run this command on any Linux machine (Ubuntu/Debian/RHEL/Alpine). It automatically sets up Python virtualenv, installs dependencies, writes systemd unit, and enables auto-start on boot.
              </p>
            </div>

            <div className="relative">
              <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black/80 p-4 font-mono text-xs text-sky-300">
                {snippets?.systemd_oneliner || "curl -sSL https://.../api/agent/install.sh | sudo bash"}
              </pre>
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleCopy(snippets?.systemd_oneliner || "", "systemd")}
                className="absolute right-2 top-2 h-7 border-slate-700 bg-slate-900 text-xs text-slate-200 hover:bg-slate-800"
              >
                {copiedKey === "systemd" ? (
                  <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <Copy className="mr-1.5 h-3.5 w-3.5" />
                )}
                {copiedKey === "systemd" ? "Copied!" : "Copy"}
              </Button>
            </div>
          </TabsContent>

          {/* TAB 3: DOCKER CONTAINER */}
          <TabsContent value="docker" className="mt-4 space-y-4">
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-4 text-xs text-slate-300">
              <p className="font-medium text-sky-400">Docker Run Command & Compose</p>
              <p className="mt-1 text-slate-400">
                Runs the scanning agent in an isolated container with host network access for direct vulnerability scanning.
              </p>
            </div>

            <div className="space-y-3">
              <div className="relative">
                <Label className="text-[11px] text-slate-400">Docker CLI Command</Label>
                <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-black/80 p-3 font-mono text-xs text-sky-300">
                  {snippets?.docker_run || "docker run -d ..."}
                </pre>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleCopy(snippets?.docker_run || "", "docker")}
                  className="absolute right-2 top-6 h-7 border-slate-700 bg-slate-900 text-xs text-slate-200 hover:bg-slate-800"
                >
                  {copiedKey === "docker" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                  {copiedKey === "docker" ? "Copied!" : "Copy"}
                </Button>
              </div>

              <div className="relative">
                <Label className="text-[11px] text-slate-400">docker-compose.yml</Label>
                <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-black/80 p-3 font-mono text-xs text-slate-300">
                  {snippets?.docker_compose || "version: '3.8'..."}
                </pre>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleCopy(snippets?.docker_compose || "", "compose")}
                  className="absolute right-2 top-6 h-7 border-slate-700 bg-slate-900 text-xs text-slate-200 hover:bg-slate-800"
                >
                  {copiedKey === "compose" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                  {copiedKey === "compose" ? "Copied!" : "Copy"}
                </Button>
              </div>
            </div>
          </TabsContent>

          {/* TAB 4: KUBERNETES */}
          <TabsContent value="kubernetes" className="mt-4 space-y-4">
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-4 text-xs text-slate-300">
              <p className="font-medium text-sky-400">Kubernetes Deployment Manifest</p>
              <p className="mt-1 text-slate-400">
                Deploy continuous scanner agents into your Kubernetes cluster to assess internal services.
              </p>
            </div>

            <div className="relative">
              <pre className="max-h-64 overflow-x-auto rounded-lg border border-slate-800 bg-black/80 p-3 font-mono text-xs text-slate-300">
                {snippets?.kubernetes_yaml || "apiVersion: apps/v1..."}
              </pre>
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleCopy(snippets?.kubernetes_yaml || "", "k8s")}
                className="absolute right-2 top-2 h-7 border-slate-700 bg-slate-900 text-xs text-slate-200 hover:bg-slate-800"
              >
                {copiedKey === "k8s" ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                {copiedKey === "k8s" ? "Copied!" : "Copy"}
              </Button>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
