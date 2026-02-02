<script lang="ts">
    import {onMount} from "svelte";
    import "../app.css";
    import oembed from "$lib/oembed.json";

    type User = {
        provider: string;
        provider_id: string;
        username: string;
        avatar_url: string;
        created_at: string;
    };

    let {children} = $props();
    let user: User | null = $state(null);

    const backendUrl = import.meta.env.VITE_NXC_BACKEND || "https://nxc.night0721.xyz";

    onMount(async () => {
        try {
            const response = await fetch(`${backendUrl}/auth/me`, {
                credentials: "include"
            });
            if (response.ok) {
                user = await response.json();
            } else if (response.status === 401) {
                console.warn("User is not logged in");
                user = null;
            }
        } catch (e) {
            console.error("Failed to fetch user: ", e);
        }
    });

    export function login() {
        window.location.href = `${backendUrl}/auth/github/login`;
    }

    export async function logout() {
        try {
            const response = await fetch(`${backendUrl}/auth/logout`, {
            method: "POST",
            credentials: "include"
        });

        if (response.ok) {
            user = null;
            window.location.href = "/";
        }
        } catch (e) {
            console.error("Failed to logout:", e);
        }
    }

    export async function addWebhook(url: String) {
        await fetch(`${backendUrl}/api/webhooks`, {
            method: "POST",
			credentials: "include",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({target_url: url})
        });
    }

    let showWebhookInput = $state(false);
    let webhookUrl = $state("");

    export async function submitWebhook() {
        if (!webhookUrl.startsWith("https://discord.com/api/webhooks/")) {
            alert("Please input a valid Discord webhook link.");
            return;
        }

        await addWebhook(webhookUrl);
        webhookUrl = "";
        showWebhookInput = false;
        alert("Webhook added! Check Discord.");
    }
</script>

<svelte:head>
    <title>NightX Client File Uploader</title>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/night.jpg"/>

    <!--    HTML Meta Tags-->
    <meta name="theme-color" content="#deb4d1" data-react-helmet="true"/>
    <meta name="description" content={oembed.bio}/>

    <!--     Google / Search Engine Tags-->
    <meta itemProp="name" content={oembed.title}/>
    <meta itemProp="description" content={oembed.bio}/>
    <meta itemProp="image" content={oembed.author_url}/>

    <!--    Facebook Meta Tags-->
    <meta property="og:url" content={oembed.provider_url}/>
    <meta property="og:type" content="website"/>
    <meta property="og:title" content={oembed.title}/>
    <meta property="og:site_name" content={oembed.provider_name}/>
    <meta property="og:description" content={oembed.bio}/>
    <meta property="og:image" content={oembed.author_url}/>

    <!--    Twitter Meta Tags-->
    <meta name="twitter:card" content="summary_large_image"/>
    <meta name="twitter:title" content={oembed.title}/>
    <meta name="twitter:description" content={oembed.bio}/>
    <meta name="twitter:image" content={oembed.author_url}/>
    <meta name="twitter:image:src" content={oembed.author_url}/>
    <meta content="video.other" property="og:type"/>
    <meta content="image/gif" property="og:image:type"/>
    <link type="application/json+oembed" href="/frontend/src/lib/oembed.json"/>
</svelte:head>

<div class="app">
    <header>
        <div class="header-content">
            <div class="header-left">
                <div class="logo"></div>
                <h1 class="logo-text">NightX Client File Uploader</h1>
            </div>

            <nav>
                <a href="/">Home</a>
                <!--<a href="/features">Features</a>-->

                <div class="header-actions">
                    {#if user}
                        <div class="user-avatar">{user.username.charAt(0).toUpperCase()}</div>
                        <span class="username">{user.username}</span>
                        {#if showWebhookInput}
                            <div class="webhook-mini-form">
                                <input
                                        type="text"
                                        bind:value={webhookUrl}
                                        placeholder="Discord Webhook URL..."
                                        class="webhook-input"
                                />
                                <button class="btn btn-primary btn-small" onclick={submitWebhook}>Save</button>
                                <button class="btn btn-red btn-small" onclick={() => showWebhookInput = false}>X
                                </button>
                            </div>
                        {:else}
                            <button class="btn btn-primary" onclick={() => showWebhookInput = true}>
                                Add Webhook
                            </button>
                        {/if}
                        <button class="btn btn-red btn-small" onclick={logout}>
                            Logout
                        </button>
                    {:else}
                        <button class="btn btn-primary" onclick={login}>
                            Login
                        </button>
                    {/if}
                </div>
            </nav>
        </div>
    </header>

    <main>
        {@render children()}
    </main>

    <footer>
        <div class="container">
            <p>Made with &hearts; on <a href="https://github.com/night0721/nxc" target="_blank"
                                        rel="noopener noreferrer">GitHub</a></p>
        </div>
    </footer>
</div>
