import { mount } from "svelte";
import App from "./App.svelte";
import { typography } from "./lib/typography";
import { nativeWindow } from "./lib/native";
import { applyTheme } from "./lib/theme.svelte";
import "./app.css";
import "./pickme.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

applyTheme();
nativeWindow();

const app = mount(App, { target });
typography(target);

export default app;
