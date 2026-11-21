// Прототипы дизайна (0.9.8): мини-панель из трея и новая карточка Zapret.
// Открываются в превью по адресу /proto.html, в сборку приложения не входят.
import { mount } from "svelte";
import Proto from "./Proto.svelte";
import { applyTheme } from "../lib/theme.svelte";
import { setLang } from "../lib/i18n";
import "../app.css";
import "../pickme.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

applyTheme();
setLang(new URLSearchParams(location.search).get("lang") === "en" ? "en" : "ru");

mount(Proto, { target });
