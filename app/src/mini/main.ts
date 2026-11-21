// Вход мини-панели из трея: отдельная страница `mini.html`, кода главного окна в ней нет.
import { mount } from "svelte";
import Panel from "./Panel.svelte";
import { nativeWindow } from "../lib/native";
import { applyTheme } from "../lib/theme.svelte";
import { getLanguage } from "../lib/api";
import { setLang } from "../lib/i18n";
import "../app.css";
import "../pickme.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

applyTheme();
nativeWindow();

// Язык — до монтирования: тексты берут его сразу и не меняются на ходу.
const info = await getLanguage().catch(() => null);
setLang(info?.lang ?? "ru");

mount(Panel, { target });
