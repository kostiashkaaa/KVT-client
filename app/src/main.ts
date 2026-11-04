import { mount } from "svelte";
import App from "./App.svelte";
import { typography } from "./lib/typography";
import { nativeWindow } from "./lib/native";
import "./app.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

nativeWindow();

const app = mount(App, { target });
typography(target);

export default app;
