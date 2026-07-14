/* @refresh reload */
import { render } from "solid-js/web";
import "@/app.css";
import "./fixture.css";
import { AppShellFixture } from "./AppShellFixture";
import { VeilLinkDialogFixture } from "./VeilLinkDialogFixture";

document.documentElement.dataset.visualFixture = "true";
document.documentElement.dataset.reduceMotion = "true";
document.documentElement.dataset.veilTheme = "midnight";
document.documentElement.style.setProperty("--veil-wallpaper-dim", "0.4");
document.documentElement.style.setProperty("--veil-wallpaper-blur", "1px");

const wallpaper = new Image();
wallpaper.src = "/visual/wallpaper.svg";
await wallpaper.decode().catch(() => undefined);

const root = document.getElementById("root");
if (!root) throw new Error("Visual fixture root element not found");

const state = new URLSearchParams(window.location.search).get("state");
render(() => state === "veil-link-long" ? <VeilLinkDialogFixture /> : <AppShellFixture />, root);

await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
root.dataset.fixtureReady = "true";
