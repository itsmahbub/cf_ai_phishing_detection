import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useAgent } from "agents/react";
import { useAgentChat } from "@cloudflare/ai-chat/react";
import type { UIMessage } from "ai";
import type {
  AssessmentRecord,
  ChatAgent,
  DynamicAnalysis,
  PhishingAgentState,
  ReputationListItem
} from "./server";
import {
  Badge,
  Button,
  Empty,
  InputArea,
  Surface,
  Text
} from "@cloudflare/kumo";
import { Toasty } from "@cloudflare/kumo/components/toast";
import { Streamdown } from "streamdown";
import { code } from "@streamdown/code";
import {
  ArrowLeftIcon,
  EyeIcon,
  PaperPlaneRightIcon,
  WarningIcon,
  ShieldSlashIcon,
  ArrowClockwiseIcon,
  CircleIcon,
  PaperclipIcon,
  XIcon,
  DeviceMobileIcon
} from "@phosphor-icons/react";

interface Attachment {
  id: string;
  file: File;
  preview: string;
  mediaType: string;
}

function createAttachment(file: File): Attachment {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    file,
    preview: URL.createObjectURL(file),
    mediaType: file.type || "application/octet-stream"
  };
}

function fileToDataUri(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function verdictLabel(verdict: AssessmentRecord["verdict"] | null | undefined) {
  if (verdict === "likely-phishing") return "Likely phishing";
  if (verdict === "likely-legitimate") return "Likely legitimate";
  if (verdict === "needs-human-review") return "Needs review";
  return "No verdict yet";
}

function verdictTone(verdict: AssessmentRecord["verdict"] | null | undefined) {
  if (verdict === "likely-phishing") return "destructive";
  if (verdict === "likely-legitimate") return "primary";
  return "secondary";
}

function dynamicStatusLabel(status: DynamicAnalysis["status"] | undefined) {
  if (status === "queued") return "Queued";
  if (status === "inspecting") return "Inspecting";
  if (status === "completed") return "Completed";
  if (status === "failed") return "Failed";
  return "Not requested";
}

function isRawToolCallText(text: string) {
  const trimmed = text.trim();

  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
    return false;
  }

  return (
    (trimmed.includes('"type": "function"') ||
      trimmed.includes('"type":"function"')) &&
    (trimmed.includes('"name": "inspectMessage"') ||
      trimmed.includes('"name":"inspectMessage"') ||
      trimmed.includes('"name": "recordAssessment"') ||
      trimmed.includes('"name":"recordAssessment"'))
  );
}

function ProcessingBubble({ status }: { status: string }) {
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    if (status !== "submitted" && status !== "streaming") {
      setStepIndex(0);
      return;
    }

    setStepIndex(0);

    const timers = [
      window.setTimeout(() => setStepIndex(1), 1200),
      window.setTimeout(() => setStepIndex(2), 2600),
      window.setTimeout(() => setStepIndex(3), 4400)
    ];

    return () => {
      for (const timer of timers) {
        window.clearTimeout(timer);
      }
    };
  }, [status]);

  const steps = [
    {
      title: "Extract message",
      detail: "Reading the message and extracting URLs"
    },
    {
      title: "Check known URLs",
      detail: "Looking in the shared reputation database"
    },
    {
      title: "Analyze risk",
      detail: "Using AI to review the message for phishing signals"
    },
    {
      title: "Prepare verdict",
      detail: "Writing the verdict and safest next step"
    }
  ];

  return (
    <div className="bubble-row assistant">
      <div className="message-bubble assistant-bubble processing-bubble">
        <Text size="sm" bold>
          Analyzing message...
        </Text>
        <div className="processing-steps">
          {steps.map((step, index) => {
            const state =
              index < stepIndex
                ? "done"
                : index === stepIndex
                  ? "active"
                  : "todo";

            return (
              <div key={step.title} className={`processing-step ${state}`}>
                <span className="processing-step-marker">
                  {state === "active" && (
                    <span className="processing-spinner" aria-hidden="true" />
                  )}
                </span>
                <div>
                  <Text size="xs" bold>
                    {step.title}
                  </Text>
                  <Text size="xs" variant="secondary">
                    {step.detail}
                  </Text>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function updateAdminUrl(selectedUrl: string | null) {
  const url = new URL(window.location.href);
  if (selectedUrl) {
    url.searchParams.set("url", selectedUrl);
  } else {
    url.searchParams.delete("url");
  }
  window.history.replaceState({}, "", url);
}

function AdminPortal() {
  const [items, setItems] = useState<ReputationListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<
    "all" | "likely-phishing" | "likely-legitimate"
  >("all");
  const [selectedUrls, setSelectedUrls] = useState<string[]>([]);
  const [isDeleting, setIsDeleting] = useState(false);
  const detailsUrl = new URL(window.location.href).searchParams.get("url");

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch("/admin/api/reputation");
        const contentType = response.headers.get("content-type") ?? "";
        if (!response.ok) {
          throw new Error(
            response.status === 403
              ? "Admin access is restricted. Protect /admin with Cloudflare Access and configure ADMIN_EMAIL."
              : `Failed to load admin data (${response.status})`
          );
        }
        if (!contentType.includes("application/json")) {
          throw new Error(
            "Admin API returned HTML instead of JSON. Protect /admin with Cloudflare Access and make sure /admin/api/* is routed to the Worker."
          );
        }

        const data = (await response.json()) as { items: ReputationListItem[] };
        if (!cancelled) {
          setItems(data.items);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(
            loadError instanceof Error ? loadError.message : "Unknown error"
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const selectedItem = detailsUrl
    ? (items.find((item) => item.url === detailsUrl) ?? null)
    : null;

  const visibleItems = items.filter((item) => {
    if (filter === "all") return true;
    return item.verdict === filter;
  });

  const allVisibleSelected =
    visibleItems.length > 0 &&
    visibleItems.every((item) => selectedUrls.includes(item.url));

  const buildTags = (item: ReputationListItem) => {
    const tags = [...item.extractionIndicators];
    if (item.dynamicAnalysis.inferredBrand) {
      tags.push(`brand:${item.dynamicAnalysis.inferredBrand}`);
    }
    return [...new Set(tags)].slice(0, 4);
  };

  const dynamicVerdictLabel = (item: ReputationListItem) =>
    item.dynamicAnalysis.verdict
      ? verdictLabel(item.dynamicAnalysis.verdict)
      : "Pending";

  const liveStatusLabel = (item: ReputationListItem) => {
    if (item.dynamicAnalysis.liveStatus === "live") return "Live";
    if (item.dynamicAnalysis.liveStatus === "not-live") return "Not live";
    return "Unknown";
  };

  const toggleSelectedUrl = useCallback((url: string) => {
    setSelectedUrls((current) =>
      current.includes(url)
        ? current.filter((item) => item !== url)
        : [...current, url]
    );
  }, []);

  const toggleAllVisible = useCallback(() => {
    setSelectedUrls((current) => {
      if (allVisibleSelected) {
        return current.filter(
          (url) => !visibleItems.some((item) => item.url === url)
        );
      }

      return [
        ...new Set([...current, ...visibleItems.map((item) => item.url)])
      ];
    });
  }, [allVisibleSelected, visibleItems]);

  const openDetailsInNewTab = useCallback((url: string) => {
    const target = new URL(window.location.href);
    target.searchParams.set("url", url);
    window.open(target.toString(), "_blank", "noopener,noreferrer");
  }, []);

  const deleteSelected = useCallback(async () => {
    if (selectedUrls.length === 0) return;

    const confirmed = window.confirm(
      `Delete ${selectedUrls.length} selected record(s)?`
    );
    if (!confirmed) return;

    try {
      setIsDeleting(true);
      for (const url of selectedUrls) {
        const response = await fetch(
          `/admin/api/reputation?url=${encodeURIComponent(url)}`,
          { method: "DELETE" }
        );
        if (!response.ok) {
          throw new Error(`Delete failed for ${url}`);
        }
      }

      setItems((current) =>
        current.filter((entry) => !selectedUrls.includes(entry.url))
      );
      setSelectedUrls([]);
    } catch (deleteError) {
      setError(
        deleteError instanceof Error ? deleteError.message : "Delete failed"
      );
    } finally {
      setIsDeleting(false);
    }
  }, [selectedUrls]);

  if (selectedItem) {
    return (
      <div className="admin-simple-shell">
        <div className="admin-toolbar">
          <Button
            variant="secondary"
            icon={<ArrowLeftIcon size={16} />}
            onClick={() => {
              updateAdminUrl(null);
              window.location.href = new URL(window.location.href).toString();
            }}
          >
            Back to table
          </Button>
        </div>

        <Surface className="admin-detail-card">
          <div className="history-item-top">
            <Badge variant={verdictTone(selectedItem.verdict)}>
              {verdictLabel(selectedItem.verdict)}
            </Badge>
            <span>{selectedItem.url}</span>
          </div>
          <Text size="sm" bold>
            Static analysis
          </Text>
          <Text size="sm" variant="secondary">
            {selectedItem.summary}
          </Text>
          <Text size="xs" variant="secondary">
            {selectedItem.messageText}
          </Text>
          <Text size="xs" variant="secondary">
            Tags:{" "}
            {buildTags(selectedItem).length > 0
              ? buildTags(selectedItem).join(", ")
              : "none"}
          </Text>
          <div className="prompt-stack">
            {selectedItem.reasons.map((reason) => (
              <div
                key={`${selectedItem.url}-${reason}`}
                className="prompt-chip"
              >
                {reason}
              </div>
            ))}
          </div>

          <Text size="sm" bold>
            Dynamic analysis
          </Text>
          <Text size="xs" variant="secondary">
            Status: {dynamicStatusLabel(selectedItem.dynamicAnalysis.status)} •
            Live: {liveStatusLabel(selectedItem)} • Verdict:{" "}
            {dynamicVerdictLabel(selectedItem)}
          </Text>
          {selectedItem.dynamicAnalysis.inferredBrand && (
            <Text size="xs" variant="secondary">
              Inferred brand: {selectedItem.dynamicAnalysis.inferredBrand}
            </Text>
          )}
          {selectedItem.dynamicAnalysis.brandDomainMatch && (
            <Text size="xs" variant="secondary">
              Brand vs URL: {selectedItem.dynamicAnalysis.brandDomainMatch}
            </Text>
          )}
          {selectedItem.dynamicAnalysis.summary && (
            <Text size="sm" variant="secondary">
              {selectedItem.dynamicAnalysis.summary}
            </Text>
          )}
          {selectedItem.dynamicAnalysis.screenshotDataUrl && (
            <div className="analysis-screenshot">
              <img
                src={selectedItem.dynamicAnalysis.screenshotDataUrl}
                alt={`Captured page screenshot for ${selectedItem.url}`}
              />
            </div>
          )}
          {selectedItem.dynamicAnalysis.reasons.length > 0 && (
            <div className="prompt-stack">
              {selectedItem.dynamicAnalysis.reasons.map((reason) => (
                <div
                  key={`${selectedItem.url}-dynamic-${reason}`}
                  className="prompt-chip"
                >
                  {reason}
                </div>
              ))}
            </div>
          )}
        </Surface>
      </div>
    );
  }

  return (
    <div className="admin-simple-shell">
      <Surface className="admin-table-card">
        <div className="admin-toolbar">
          <div className="admin-toolbar-group">
            <Text size="sm" bold>
              Reputation records
            </Text>
            <select
              className="admin-select"
              value={filter}
              onChange={(event) =>
                setFilter(
                  event.target.value as
                    | "all"
                    | "likely-phishing"
                    | "likely-legitimate"
                )
              }
            >
              <option value="all">All</option>
              <option value="likely-phishing">Phishing</option>
              <option value="likely-legitimate">Legitimate</option>
            </select>
          </div>

          <div className="admin-toolbar-group">
            <Button
              variant="secondary"
              disabled={selectedUrls.length === 0 || isDeleting}
              onClick={deleteSelected}
            >
              Delete selected
            </Button>
            <Button
              variant="secondary"
              onClick={() => window.location.reload()}
            >
              Refresh
            </Button>
          </div>
        </div>

        {loading && (
          <Text size="sm" variant="secondary">
            Loading admin data...
          </Text>
        )}

        {error && (
          <Text size="sm" variant="secondary">
            {error}
          </Text>
        )}

        {!loading && !error && visibleItems.length === 0 && (
          <Text size="sm" variant="secondary">
            No records found for this filter.
          </Text>
        )}

        {!loading && !error && visibleItems.length > 0 && (
          <div className="admin-table-wrap">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleAllVisible}
                    />
                  </th>
                  <th>URL</th>
                  <th>Static verdict</th>
                  <th>Dynamic state</th>
                  <th>Dynamic verdict</th>
                  <th>Live</th>
                  <th>Tags</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visibleItems.map((item) => (
                  <tr key={item.url} className="admin-table-row">
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedUrls.includes(item.url)}
                        onChange={() => toggleSelectedUrl(item.url)}
                      />
                    </td>
                    <td>
                      <div className="admin-table-url">{item.url}</div>
                    </td>
                    <td>
                      <Badge variant={verdictTone(item.verdict)}>
                        {verdictLabel(item.verdict)}
                      </Badge>
                    </td>
                    <td>{dynamicStatusLabel(item.dynamicAnalysis.status)}</td>
                    <td>{dynamicVerdictLabel(item)}</td>
                    <td>{liveStatusLabel(item)}</td>
                    <td>
                      <div className="admin-tag-list">
                        {buildTags(item).map((tag) => (
                          <span
                            key={`${item.url}-${tag}`}
                            className="admin-tag"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <Button
                        variant="ghost"
                        shape="square"
                        icon={<EyeIcon size={16} />}
                        aria-label={`Open ${item.url}`}
                        onClick={() => openDetailsInNewTab(item.url)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Surface>
    </div>
  );
}

function Chat() {
  const [connected, setConnected] = useState(false);
  const [input, setInput] = useState("");
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const agent = useAgent<ChatAgent, PhishingAgentState>({
    agent: "ChatAgent",
    onOpen: useCallback(() => setConnected(true), []),
    onClose: useCallback(() => setConnected(false), [])
  });

  const { messages, sendMessage, clearHistory, stop, status } = useAgentChat({
    agent
  });

  const isStreaming = status === "streaming" || status === "submitted";

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!isStreaming) {
      textareaRef.current?.focus();
    }
  }, [isStreaming]);

  const addFiles = useCallback((files: FileList | File[]) => {
    const images = Array.from(files).filter((file) =>
      file.type.startsWith("image/")
    );
    if (images.length === 0) return;
    setAttachments((prev) => [...prev, ...images.map(createAttachment)]);
  }, []);

  const removeAttachment = useCallback((id: string) => {
    setAttachments((prev) => {
      const target = prev.find((item) => item.id === id);
      if (target) URL.revokeObjectURL(target.preview);
      return prev.filter((item) => item.id !== id);
    });
  }, []);

  const resetChat = useCallback(async () => {
    for (const attachment of attachments) {
      URL.revokeObjectURL(attachment.preview);
    }
    setAttachments([]);
    await agent.stub.resetSessionView();
    await clearHistory();
  }, [agent.stub, attachments, clearHistory]);

  const send = useCallback(async () => {
    const text = input.trim();
    if ((!text && attachments.length === 0) || isStreaming) return;

    const parts: Array<
      | { type: "text"; text: string }
      | { type: "file"; mediaType: string; url: string }
    > = [];

    if (text) {
      parts.push({ type: "text", text });
    }

    for (const attachment of attachments) {
      const dataUri = await fileToDataUri(attachment.file);
      parts.push({
        type: "file",
        mediaType: attachment.mediaType,
        url: dataUri
      });
      URL.revokeObjectURL(attachment.preview);
    }

    setInput("");
    setAttachments([]);
    sendMessage({ role: "user", parts });

    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  }, [attachments, input, isStreaming, sendMessage]);

  return (
    <div className="app-shell simple-shell">
      <Surface className="simple-chat-shell">
        <div className="simple-header">
          <div>
            <h1>PhishGuard</h1>
            <p>
              Paste a suspicious SMS, email, or screenshot and get a fast
              verdict before you click, reply, or pay. Known URLs are answered
              from a shared reputation database before deeper analysis runs.
            </p>
          </div>
          <div className="hero-actions">
            <div className="connection-pill">
              <CircleIcon
                size={10}
                weight="fill"
                className={connected ? "text-kumo-success" : "text-kumo-danger"}
              />
              <span>{connected ? "Connected" : "Connecting..."}</span>
            </div>
            <Button
              variant="secondary"
              icon={<ArrowClockwiseIcon size={16} />}
              onClick={resetChat}
            >
              Clear chat
            </Button>
          </div>
        </div>

        <Surface className="chat-surface">
          <div className="chat-header">
            <div>
              <Text size="sm" bold>
                Analyze a suspicious message
              </Text>
              <Text size="xs" variant="secondary">
                Paste the text directly or attach an email / SMS screenshot.
              </Text>
            </div>
          </div>

          <div className="messages-wrap">
            {messages.length === 0 && (
              <Empty
                icon={<WarningIcon size={32} />}
                title="No message submitted yet"
                contents="Start with the suspicious text itself. The more of the original wording you paste, the better the verdict."
              />
            )}

            {messages.map((message: UIMessage, index: number) => {
              const isUser = message.role === "user";
              const isLastAssistant =
                message.role === "assistant" && index === messages.length - 1;

              return (
                <div key={message.id} className="message-stack">
                  {message.parts
                    .filter(
                      (part): part is Extract<typeof part, { type: "file" }> =>
                        part.type === "file" &&
                        (part as { mediaType?: string }).mediaType?.startsWith(
                          "image/"
                        ) === true
                    )
                    .map((part, partIndex) => (
                      <div
                        key={`${message.id}-file-${partIndex}`}
                        className={`bubble-row ${isUser ? "user" : "assistant"}`}
                      >
                        <img
                          src={part.url}
                          alt="Uploaded suspicious message"
                          className="image-bubble"
                        />
                      </div>
                    ))}

                  {message.parts
                    .filter((part) => part.type === "text")
                    .map((part, partIndex) => {
                      const text = (part as { text: string }).text;
                      if (!text || isRawToolCallText(text)) return null;

                      if (isUser) {
                        return (
                          <div
                            key={`${message.id}-text-${partIndex}`}
                            className="bubble-row user"
                          >
                            <div className="message-bubble user-bubble">
                              {text}
                            </div>
                          </div>
                        );
                      }

                      return (
                        <div
                          key={`${message.id}-text-${partIndex}`}
                          className="bubble-row assistant"
                        >
                          <div className="message-bubble assistant-bubble">
                            <Streamdown
                              className="sd-theme"
                              plugins={{ code }}
                              controls={false}
                              isAnimating={isLastAssistant && isStreaming}
                            >
                              {text}
                            </Streamdown>
                          </div>
                        </div>
                      );
                    })}
                </div>
              );
            })}

            {isStreaming && <ProcessingBubble status={status} />}

            <div ref={messagesEndRef} />
          </div>

          <form
            className="composer"
            onSubmit={(event) => {
              event.preventDefault();
              send();
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              multiple
              className="hidden"
              onChange={(event) => {
                if (event.target.files) addFiles(event.target.files);
                event.target.value = "";
              }}
            />

            {attachments.length > 0 && (
              <div className="attachment-row">
                {attachments.map((attachment) => (
                  <div key={attachment.id} className="attachment-thumb">
                    <img src={attachment.preview} alt={attachment.file.name} />
                    <button
                      type="button"
                      aria-label={`Remove ${attachment.file.name}`}
                      onClick={() => removeAttachment(attachment.id)}
                    >
                      <XIcon size={12} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="composer-shell">
              <Button
                type="button"
                variant="ghost"
                shape="square"
                icon={<PaperclipIcon size={16} />}
                aria-label="Attach screenshot"
                disabled={!connected || isStreaming}
                onClick={() => fileInputRef.current?.click()}
              />

              <InputArea
                ref={textareaRef}
                value={input}
                onValueChange={setInput}
                rows={1}
                disabled={!connected || isStreaming}
                placeholder="Paste the suspicious SMS or email here..."
                className="composer-input"
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    send();
                  }
                }}
                onInput={(event) => {
                  const element = event.currentTarget;
                  element.style.height = "auto";
                  element.style.height = `${element.scrollHeight}px`;
                }}
              />

              {isStreaming ? (
                <Button
                  type="button"
                  variant="secondary"
                  shape="square"
                  aria-label="Stop generation"
                  icon={<ShieldSlashIcon size={16} />}
                  onClick={stop}
                />
              ) : (
                <Button
                  type="submit"
                  variant="primary"
                  shape="square"
                  aria-label="Analyze message"
                  disabled={
                    (!input.trim() && attachments.length === 0) || !connected
                  }
                  icon={<PaperPlaneRightIcon size={16} />}
                />
              )}
            </div>
          </form>
        </Surface>
      </Surface>
    </div>
  );
}

export default function App() {
  if (window.location.pathname.startsWith("/admin")) {
    return (
      <Toasty>
        <AdminPortal />
      </Toasty>
    );
  }

  return (
    <Toasty>
      <Suspense
        fallback={
          <div className="loading-screen">
            <DeviceMobileIcon size={22} />
            <span>Loading PhishGuard…</span>
          </div>
        }
      >
        <Chat />
      </Suspense>
    </Toasty>
  );
}
