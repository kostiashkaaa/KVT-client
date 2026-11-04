import { mount } from "svelte";
import App from "./App.svelte";
import { typography } from "./lib/typography";
import "./app.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

const app = mount(App, { target });
typography(target);

export default app;
