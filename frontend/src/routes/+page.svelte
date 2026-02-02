<script lang="ts">
    import {onMount} from "svelte";
    import {userState} from "$lib/User.svelte.ts";

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

    type Url = {
        slug: string;
        target_url: string;
        password_hash: string;
        expires_at: string;
        created_at: string;
    };

    let files: File[] = $state([]);
    let urls: Url[] = $state([]);
    let selectedTab = $state("upload");
    let uploadResult = $state("");
    let pasteResult = $state("");
    let urlResult = $state("");
    let pasteContent = $state("");
    let pasteTitle = $state("");
    let pasteLanguage = $state("");
    let urlInput = $state("");
    let password = $state("");
    let expiresAt = $state("");

    onMount(async () => {
        await loadData();
    });

    // Helper to ensure we send the format Rust expects: %Y-%m-%dT%H:%M:%S
    function formatExpiry(val: string) {
        if (!val) return "";
        // If user picked a date but no seconds, HTML might give YYYY-MM-DDTHH:mm
        return val.length === 16 ? `${val}:00` : val;
    }

    async function loadData() {
        try {
            const [filesRes, urlsRes] = await Promise.all([
                fetch(`${backendUrl}/api/files`, {
                    credentials: "include"
                }),
                fetch(`${backendUrl}/api/urls`, {
                    credentials: "include"
                })
            ]);

            if (filesRes.ok)
                files = await filesRes.json();
            if (urlsRes.ok)
                urls = await urlsRes.json();
        } catch (e) {
            console.error("Failed to load data:", e);
        }
    }

    async function handleUpload(event: SubmitEvent, type: 'file' | 'paste' | 'url') {
        event.preventDefault();
        const form = event.target as HTMLFormElement;
        const formData = new FormData(form);

        // Append formatted expiry if it exists
        if (expiresAt) {
            formData.set("expires_at", formatExpiry(expiresAt));
        }

        try {
            const response = await fetch(`${backendUrl}`, {
                method: "POST",
                credentials: "include",
                body: formData
            });

            if (response.ok) {
                const result = await response.json();
                if (type === 'file') uploadResult = result.url;
                if (type === 'paste') pasteResult = result.url;
                if (type === 'url') urlResult = result.url;

                urlInput = "";
                pasteContent = "";
                pasteTitle = "";
                pasteLanguage = "";


                // Reset common fields
                password = "";
                expiresAt = "";
                await loadData();
            }
        } catch (e) {
            console.error(`${type} failed:`, e);
        }
    }


    async function deleteItem(type: String, id: String) {
        await fetch(`${backendUrl}/api/${type}/delete`, {
            method: "POST",
            credentials: "include",
            headers: {
                "content-type": "application/json"
            },
            body: JSON.stringify({id})
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

    {#snippet extraFields()}
        <div class="grid grid-2" style="gap: 1rem; margin-top: 1rem;">
            <div class="form-group">
                <label for="pw">Password (Optional)</label>
                <input id="pw" type="password" name="password" bind:value={password} placeholder="Protect your link"/>
            </div>
            <div class="form-group">
                <label for="exp">Expires At (Optional)</label>
                <input id="exp" type="datetime-local" name="expires_at" bind:value={expiresAt}/>
            </div>
        </div>
    {/snippet}
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
                    <form onsubmit={(e) => handleUpload(e, 'file')}>
                        <div class="form-group">
                            <input type="file" name="file" required/>
                        </div>
                        {@render extraFields()}
                        <button type="submit" class="btn btn-green btn-full">Upload</button>
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
                    <code>curl -F"file=@file.png" -F "expires_at=2026-02-15T12:00" -F "password=mysecurepass" https://nxc.night0721.xyz/</code>
                    <pre>Server will respond with a JSON object with URL to view file or download file</pre>
					<pre>If you don't include title, filename would be used as title</pre>
                {/if}

                <!-- Paste Creation -->
                {#if selectedTab === "paste"}
                    <div class="card-header">
                        <span class="card-icon">📝</span>
                        <h3 class="card-title">Create Paste</h3>
                    </div>
                    <form onsubmit={(e) => handleUpload(e, 'paste')}>
                        <div class="form-group">
                            <input type="text" name="title" bind:value={pasteTitle} placeholder="Title"/>
                        </div>
                        <div class="form-group">
                            <textarea name="content" bind:value={pasteContent} placeholder="Content..."
                                      required></textarea>
                        </div>
                        <div class="form-group">
                            <input type="text" name="syntax" bind:value={pasteLanguage}
                                   placeholder="Language (e.g. rust)"/>
                        </div>
                        {@render extraFields()}
                        <button type="submit" class="btn btn-primary btn-full">Create Paste</button>
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
                    <code>"curl -F "content=console.log('hi');" -F "title=script.js" -F "syntax=javascript" https://nxc.night0721.xyz/</code>
                    <pre>Server will respond with a JSON object with URL to view file or download file</pre>
                {/if}

                <!-- URL Shortening -->
                {#if selectedTab === "url"}
                    <div class="card-header">
                        <span class="card-icon">🔗</span>
                        <h3 class="card-title">Shorten URL</h3>
                    </div>
                    <form onsubmit={(e) => handleUpload(e, 'url')}>
                        <div class="form-group">
                            <input type="url" name="url" bind:value={urlInput} placeholder="https://..." required/>
                        </div>
                        {@render extraFields()}
                        <button type="submit" class="btn btn-mauve btn-full">Shorten</button>
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
                    <code>curl -F "url=https://github.com/night0721" -F "password=protected" https://nxc.night0721.xyz/</code>
                    <pre>Server will respond with a JSON object with URL to shortened link</pre>
                {/if}
            </div>
        </div>

        <!-- Sidebar -->
        {#if userState.user}
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
                                <a href={`${backendUrl}/i/raw/${file.slug}`} class="item-link">Raw</a>
                                <a href={`${backendUrl}/i/bin/${file.slug}`} class="item-link">Download</a>
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
        {/if}
    </div>
</div>
