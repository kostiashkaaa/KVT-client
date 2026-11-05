# Безопасность

KVT отвечает за то, куда уходит ваш трафик, поэтому к уязвимостям мы относимся серьёзно.

## Как сообщить об уязвимости

Пожалуйста, **не открывайте публичный Issue**. Сообщите приватно через
[Security Advisories](https://github.com/kostiashkaaa/KVT-client/security/advisories/new)
этого репозитория («Report a vulnerability»).

Опишите, что можно сделать и как это воспроизвести, и укажите версию KVT и Windows.
Не прикладывайте свои настоящие ключи и ссылки подписок.

Мы ответим, как только разберёмся, и выпустим исправление новой версией на странице
[Releases](https://github.com/kostiashkaaa/KVT-client/releases). Если хотите, укажем вас
в описании исправления.

## Что особенно важно

- утечки трафика или DNS мимо туннеля, в том числе при обрыве и с включённым kill switch;
- способы управлять службой KVT (у неё права администратора) из чужой программы;
- утечка ключей, ссылок подписок или адресов серверов в журналы, диагностику или окно;
- разбор подписок и ссылок, после которого KVT падает или делает лишнее.

## Поддерживаемые версии

Исправления выходят для последней версии. Обновиться можно файлом
`KVT-x.y.z-update.exe` со страницы Releases.

---

**English:** please report vulnerabilities privately via
[Security Advisories](https://github.com/kostiashkaaa/KVT-client/security/advisories/new),
not in public issues. Fixes ship in the latest release.
