<script lang="ts">
    import {onMount} from "svelte";

    const backendUrl = import.meta.env.VITE_NXC_BACKEND || "https://nxc.night0721.xyz";

    type File = {
        slug: string;
        path: string;
        kind: string;
        mime_type: string;
        size_bytes: number;
        is_temp: boolean;
        password_hash: string;
        delete_at: string;
        created_at: string;
    };

    type Paste = {
        slug: string;
        title: string;
        content: string;
        syntax: string;
        password_hash: string;
        is_temp: boolean;
        created_at: string;
    };

    type Url = {
        slug: string;
        target_url: string;
        password_hash: string;
        expires_at: string;
        created_at: string;
    };

    let files: File[] = $state([]);
    let pastes: Paste[] = $state([]);
    let urls: Url[] = $state([]);
    let selectedTab = $state("upload");
    let uploadResult = $state("");
    let pasteResult = $state("");
    let urlResult = $state("");
    let pasteContent = $state("");
    let pasteTitle = $state("");
    let pasteLanguage = $state("");
    let urlInput = $state("");

    onMount(async () => {
        await loadData();
    });

    async function loadData() {
        try {
            const [filesRes, pastesRes, urlsRes] = await Promise.all([
                fetch(`${backendUrl}/api/files`, {
                    credentials: "include"
                }),
                fetch(`${backendUrl}/api/pastes`, {
                    credentials: "include"
                }),
                fetch(`${backendUrl}/api/urls`, {
                    credentials: "include"
                })
            ]);

            if (filesRes.ok)
                files = await filesRes.json();
            if (pastesRes.ok)
                pastes = await pastesRes.json();
            if (urlsRes.ok)
                urls = await urlsRes.json();
        } catch (e) {
            console.error("Failed to load data:", e);
        }
    }

    async function handleFileUpload(event: SubmitEvent) {
        const formData = new FormData(event.target as HTMLFormElement);
        try {
            const response = await fetch(`${backendUrl}/api/file`, {
                method: "POST",
                credentials: "include",
                body: formData
            });
            if (response.ok) {
                const result = await response.json();
                uploadResult = result.url;
                await loadData();
            }
        } catch (e) {
            console.error("Upload failed:", e);
        }
    }

    async function handlePaste(event: SubmitEvent) {
        const formData = new FormData(event.target as HTMLFormElement);
        const data = Object.fromEntries(formData.entries());
		console.log(data)

        try {
            const response = await fetch(`${backendUrl}/api/paste`, {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                const result = await response.json();
                pasteResult = result.url;
                pasteContent = "";
                pasteTitle = "";
                pasteLanguage = "";
                await loadData();
            } else {
                const errorText = await response.text();
                console.error("Server rejected paste:", errorText);
            }
        } catch (e) {
            console.error("Paste failed:", e);
        }
    }

    async function handleUrlShorten(event: SubmitEvent) {
        const formData = new FormData(event.target as HTMLFormElement);
        const data = Object.fromEntries(formData.entries());
        try {
            const response = await fetch(`${backendUrl}/api/url`, {
                method: "POST",
                credentials: "include",
                headers: {
                    "content-type": "application/json"
                },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                const result = await response.json();
                urlResult = result.url;
                urlInput = "";
                await loadData();
            }
        } catch (e) {
            console.error("URL shortening failed:", e);
        }
    }

	async function deleteItem(type: String, id: String) {
		await fetch(`${backendUrl}/api/${type}/delete`, {
            method: "POST",
            credentials: "include",
			headers: {
                "content-type": "application/json"
            },
            body: JSON.stringify({ id })
        });
		await loadData();
	}
</script>

<div class="container">
    <!-- Hero Section -->
    <section class="hero">
        <h2>Temporary file hoster.</h2>
        <p>Upload files, shorten URLs with speed!</p>
    </section>

    <!-- Tabs -->
    <div class="tabs-container">
        <div class="tabs">
            <button
                    class="tab-btn"
                    class:active={selectedTab === "upload"}
                    onclick={() => selectedTab = "upload"}
            >
                📁 Upload File
            </button>
            <button
                    class="tab-btn"
                    class:active={selectedTab === "paste"}
                    onclick={() => selectedTab = "paste"}
            >
                📝 Create Paste
            </button>
            <button
                    class="tab-btn"
                    class:active={selectedTab === "url"}
                    onclick={() => selectedTab = "url"}
            >
                🔗 Shorten URL
            </button>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div class="grid grid-2">
        <!-- Main Panel -->
        <div>
            <div class="card">
                <!-- File Upload -->
                {#if selectedTab === "upload"}
                    <div class="card-header">
                        <span class="card-icon">📁</span>
                        <h3 class="card-title">Upload File</h3>
                    </div>
                    <form onsubmit={handleFileUpload}>
                        <div class="form-group">
                            <input
                                    type="file"
                                    name="file"
                                    required
                            />
                        </div>
                        <button type="submit" class="btn btn-green btn-full">
                            Upload File
                        </button>
                    </form>
                    {#if uploadResult}
                        <div class="result">
                            <div class="result-label">File uploaded successfully:</div>
                            <a href={uploadResult} class="result-link" target="_blank">{uploadResult}</a>
                        </div>
                    {/if}
                    <br>
                    <pre>You can either enter text below and click submit to create a link or use CURL/other http client to send POST request for creating links</pre>
                    <pre>CURL example:</pre>
                    <code>curl -F"file=@file.png" https://nxc.night0721.xyz/api/file</code>
                    <pre>Server will respond with a JSON object with URL to view file or download file</pre>
                {/if}

                <!-- Paste Creation -->
                {#if selectedTab === "paste"}
                    <div class="card-header">
                        <span class="card-icon">📝</span>
                        <h3 class="card-title">Create Paste</h3>
                    </div>
                    <form onsubmit={handlePaste}>
                        <div class="form-group">
                            <input
                                    type="text"
                                    name="title"
                                    bind:value={pasteTitle}
                                    placeholder="Title (optional)"
                            />
                        </div>
                        <div class="form-group">
                            <textarea
                                    name="content"
                                    bind:value={pasteContent}
                                    placeholder="Paste content"
                                    required
                            ></textarea>
                        </div>
                        <div class="form-group">
                            <input
                                    type="text"
                                    name="syntax"
                                    bind:value={pasteLanguage}
                                    placeholder="Language (optional)"
                            />
                        </div>
                        <button type="submit" class="btn btn-primary btn-full">
                            Create Paste
                        </button>
                    </form>
                    {#if pasteResult}
                        <div class="result">
                            <div class="result-label">Paste created successfully:</div>
                            <a href={pasteResult} class="result-link" target="_blank">{pasteResult}</a>
                        </div>
                    {/if}
                    <br>
                    <pre>You can either enter text below and click submit to create a link or use CURL/other http client to send POST request for creating links</pre>
                    <pre>CURL example:</pre>
                    <code>{"curl https://nxc.night0721.xyz/api/paste -H \"Content-Type: application/json\" -d '{\"title\": \"Title\", \"content\":\"Test\", \"syntax\": \"plaintext\"}'"}</code>
                    <pre>Server will respond with a JSON object with URL to view file or download file</pre>
                {/if}

                <!-- URL Shortening -->
                {#if selectedTab === "url"}
                    <div class="card-header">
                        <span class="card-icon">🔗</span>
                        <h3 class="card-title">Shorten URL</h3>
                    </div>
                    <form onsubmit={handleUrlShorten}>
                        <div class="form-group">
                            <input
                                    type="url"
                                    name="url"
                                    bind:value={urlInput}
                                    placeholder="https://example.com"
                                    required
                            />
                        </div>
                        <button type="submit" class="btn btn-mauve btn-full">
                            Shorten URL
                        </button>
                    </form>
                    {#if urlResult}
                        <div class="result">
                            <div class="result-label">URL shortened successfully:</div>
                            <a href={urlResult} class="result-link" target="_blank">{urlResult}</a>
                        </div>
                    {/if}
					<br>
					<pre>You can either enter text below and click submit to create a link or use CURL/other http client to send POST request for creating links</pre>
					<pre>CURL example:</pre>
					<code>{"curl https://nxc.night0721.xyz/api/url -H \"Content-Type: application/json\" -d '{\"url\": \"https://night0721.xyz\"}'"}</code>
					<pre>Server will respond with a JSON object with URL to shortened link</pre>
                {/if} 
            </div>
        </div>

        <!-- Sidebar -->
        <div class="sidebar">
            <!-- Recent Files -->
            <div class="sidebar-section">
                <h3 class="sidebar-title">
                    <span class="sidebar-icon">📁</span>
                    Recent Files
                </h3>
                <div class="item-list">
                    {#each files.slice(0, 5) as file}
                        <div class="item">
                            <span class="item-name">{file.path.split('/').pop()}</span>
                            <a href={`${backendUrl}/i/${file.slug}`} class="item-link">View</a>
                            <a href={`${backendUrl}/i/raw/${file.slug}`} class="item-link">Download</a>
                            <button class="item-link" onclick={deleteItem("file", file.slug)}>Delete</button>
                        </div>
                    {:else}
                        <div class="empty-state">
                            <span class="empty-icon">📂</span>
                            <p class="empty-text">No files yet</p>
                        </div>
                    {/each}
                </div>
            </div>

            <!-- Recent Pastes -->
            <div class="sidebar-section">
                <h3 class="sidebar-title">
                    <span class="sidebar-icon">📝</span>
                    Recent Pastes
                </h3>
                <div class="item-list">
                    {#each pastes.slice(0, 5) as paste}
                        <div class="item">
                            <span class="item-name">{paste.title || "Untitled"}</span>
                            <a href={`${backendUrl}/p/${paste.slug}`} class="item-link">View</a>
                            <a href={`${backendUrl}/p/raw/${paste.slug}`} class="item-link">Raw</a>
                            <button class="item-link" onclick={deleteItem("paste", paste.slug)}>Delete</button>
                        </div>
                    {:else}
                        <div class="empty-state">
                            <span class="empty-icon">📄</span>
                            <p class="empty-text">No pastes yet</p>
                        </div>
                    {/each}
                </div>
            </div>

            <!-- Recent URLs -->
            <div class="sidebar-section">
                <h3 class="sidebar-title">
                    <span class="sidebar-icon">🔗</span>
                    Recent URLs
                </h3>
                <div class="item-list">
                    {#each urls.slice(0, 5) as url}
                        <div class="item">
                            <span class="item-name item-code">{url.slug}({url.target_url})</span>
                            <a href={`${backendUrl}/s/${url.slug}`} class="item-link">Go</a>
                            <button class="item-link" onclick={deleteItem("url", url.slug)}>Delete</button>
                        </div>
                    {:else}
                        <div class="empty-state">
                            <span class="empty-icon">🔗</span>
                            <p class="empty-text">No URLs yet</p>
                        </div>
                    {/each}
                </div>
            </div>
        </div>
    </div>
</div>
