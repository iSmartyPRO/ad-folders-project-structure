# Project Structure

Скрипт повзоляющий построить структуру Active Directory и создать папки согласно шаблона.

В зависимости от конфигурации будет создана папка !_Scans

Каждая папка настраивается группа безопасности Read и Full.

# How to?

Клонируйте проект:
```
git clone https://github.com/iSmartyPRO/ad-folders-project-structure.git
cd ad-folders-project-structure
```

Подготовьте файл конфигурации под проект:
```
cp FolderStructure.json.sample project.json
edit project.json
```
Все поля необходимо отредактировать согласно вашего проекта.

Подгрузите функции:
```
. .\Project-Structure.ps1
```

Запуск!!!

! Запуск надо выполнять с правами администратора на файловом сервере, а так же в Active Directory.
! На компьютере с которого запускается скрипт, необходимо наличие PowerShell модуля "Active Directory"

```
New-ProjectStructure -JsonConfig .\Project.json
```

Если всё сделано правильно, то должно произойти следующее:

* В Active Directory появиться OU с названием проекта и под ним появяться OU: Computers, Groups, Users;
* Под проект создастся две группы Root которые будут иметь доступы Full и Read ко всем папкам. В основном эта группа нужна для руководителей проектов;
* Для каждой папки будет создана две группs Full и Read
* Будет создан список папок;
* Если в конфигурации выставлен параметр создания Scans - то будут созданы подпапки !_Scans;
* Каждая папка будет настроена в связке с соответствующей группе.


### Notes
К сожалению не получилось настроить ACL для локального пользователя net_scan файлового сервера. Возможно позже можно будет сделать - а в данной версии пользователя net_scan надо вручную допрописывать.