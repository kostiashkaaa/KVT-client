import { mount } from "svelte";
import App from "./App.svelte";
import { typography } from "./lib/typography";
import { nativeWindow } from "./lib/native";
import { applyTheme } from "./lib/theme.svelte";
import { getLanguage } from "./lib/api";
import { setLang } from "./lib/i18n";
import "./app.css";
import "./pickme.css";

const target = document.getElementById("app");
if (!target) throw new Error("нет #app");

applyTheme();
nativeWindow();

// Язык — до монтирования: тексты окна берут его сразу и не меняются на ходу.
const info = await getLanguage().catch(() => null);
setLang(info?.lang ?? "ru");

const app = mount(App, { target });
typography(target);

export default app;
