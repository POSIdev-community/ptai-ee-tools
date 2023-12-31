# Инструкция по развертыванию и конфигурированию плагина Jenkins
## Установка плагина Jenkins
Для установки плагина Jenkins необходимо:
1. Войти в менеджер плагинов Jenkins (Manage Jenkins - Manage Plugins) и перейти на закладку Advanced;
2. В разделе Upload Plugin нажатием кнопки Browse перейти в диалог открытия файла и выбрать ptai-jenkins-plugin.hpi; 
3. Подтвердить выбор файла нажатием кнопки Open и загрузить выбранный плагин кнопкой Upload в веб-интерфейсе Jenkins. <br>

После установки плагина необходимо выполнить его начальное конфигурирование.

## Начальное конфигурирование
Целью начального конфигурирования плагина Jenkins является указание URL сервера PT AI и аутентификационных данных для доступа. Указанные настройки являются глобальными для заданного экземпляра Jenkins и могут быть использованы во всех задачах сборки. При этом плагин поддерживает возможность поддержки произвольного числа экземпляров конфигурации, идентифицируемых по имени. <br>
Помимо глобальных, плагин поддерживает локальные настройки, задаваемые в рамках задачи сборки. Локальные настройки могут быть использованы в ситуации, когда необходимо использовать конфигурацию, отличную от заданной глобально, а права доступа недостаточны для внесения в нее изменений.<br> 
Для перехода в режим управления глобальными настройками выполните следующие действия:
1. Перейдите в окно управления параметрами системы Jenkins (Manage Jenkins - Configure System); 
2. В разделе PT AI vulnerability analysis добавьте экземпляр конфигурации нажатием кнопки Add PT AI global configuration и выберите в выпадающем списке пункт PT AI (slim mode) configuration; 
3. В появившемся окне редактирования параметров созданного экземпляра конфигурации укажите его имя и параметры подключения к серверу PT AI: URL и аутентификационные данные. При необходимости можно проверить корректность введенных параметров и работоспособность сервера PT AI нажатием на кнопку Test PT AI server connection; 
4. Сохраните внесенные изменения нажатием кнопки Save. 

## Включение задачи анализа кода в конвейер сборки
Для включения задачи анализа кода в конвейер сборки необходимо добавить соответствующий шаг сборки. Для этого:
1. Перейдите в желаемую задачу и нажатием на ссылку Configure у левого края окна войдите в режим внесения изменений;
2. В разделе Build нажатием кнопки Add build step добавьте в выпадающем списке пункт PT AI vulnerability analysis. 

В настройках шага сборки необходимо указать значения следующих параметров:
- Scan settings type - способ, которым задаются настройки анализа. Поддерживаются два варианта: посредством PT AI UI или посредством JSON-файлов настроек и политики. 
- Project name - имя проекта в PT AI UI. Этот параметр доступен при выборе в поле Scan settings type пункта PT AI UI-defined settings. При проведении анализа кода настройки будут взяты из настроек соответствующего проекта, который должен существовать на момент сканирования
- Scan settings - параметры анализа кода, определенные в JSON-формате (тут можно дать ссылку на раздел с описанием этого формата в документации). Этот и следующий параметры доступны при указании в качестве Scan settings type значения JSON-defined settings. Поле Scan settings должно быть заполнено и содержать корректные настройки в JSON-формате. Проверить корректность настроек можно нажатием кнопки Test JSON settings, при успешной проверке будут выведены имя проекта и язык программирования
- Policy - политика безопасности проекта, определенная в JSON-формате (тут можно дать ссылку на раздел с описанием этого формата в документации). Допускается оставлять значение этого поля пустым. Проверить корректность настроек можно нажатием кнопки Test JSON policy, при успешной проверке будут выведено количество правил в составе политики
- Server config - в этом выпадающем списке можно выбрать тип подключения к серверу PT AI. При выборе из выпадающего списка пункта Global scope defined PT AI server config будут использованы глобальные параметры соединения, заданные в соответствии с разделом (тут ссылка на Начальное конфигурирование) и имя экземпляра глобальной конфигурации должно быть выбрано в выпадающем списке Configuration name. При выборе в выпадающем списке Server config пункта Task scope defined PT AI server config (slim mode) необходимо самостоятельно заполнить URL сервера PT AI и задать аутентификационные данные, эти настройки будут являться индивидуальными для выбранной задачи сборки
- Fail step if SAST failed - при отмеченном флажке шаг сборки будет помечен как неуспешный при несоответствии результатов анализа кода политике безопасности, ассоциированной с проектом. Это позволяет останавливать сборку в целом и не допускать случайного развертывания уязвимого кода
- Fail step if SAST unstable - при отмеченном флажке шаг сборки будет помечен как неуспешный в ситуации, когда политика безопасности не нарушена, но в ходе анализа возникали второстепенные предупреждения, например, об отсутствующих зависимостях
- При нажатии на кнопку Advanced становятся доступными два дополнительных параметра: SAST agent CI node name и Verbose log output. Первый параметр используется для явного указания метки или имени агента сканирования, предназначенного для данной задачи. Второй параметр обеспечивает детальное протоколирование работы плагина;
- Files to analyse - один или несколько наборов анализируемых файлов, добавляемых кнопкой Add transfer set. Все пути к файлам являются относительными и базовым каталогом при этом является рабочая папка задачи сборки. В каждом наборе файлов задаются следующие параметры:
    - Files to analyse - перечень шаблонов имен файлов, включаемых в набор. Используется формат шаблонов, принятый в Ant (http://ant.apache.org/manual/dirtasks.html#patterns)
    - Remove prefix - префикс пути файла, который должен быть удален из итогового имени. Использование этого поля позволяет, например, избежать использования громоздких полных путей к файлам. При использовании этого параметра все файлы должны содержать указанный префикс в своем пути
    - Advanced - по нажатию этой кнопки становятся доступными дополнительные настройки набора файлов. В том числе:
        - Exclude files - перечень шаблонов имен файлов, исключаемых из набора. Используется формат шаблонов, принятый в Ant (http://ant.apache.org/manual/dirtasks.html#patterns) ;
        - Pattern separator - регулярное выражение, используемое для разделения шаблонов в перечнях Files to analyse и Exclude files;
        - Use default excludes - при установке этого флажка из перечня анализируемых файлов будут автоматически удалены те, что соответствуют типовым шаблонам, например, \*\*/.git/\*\*, \*\*/\*~ и т.д.;
        - Flatten files - при установке этого флажка все пути к файлам будут отброшены и итоговый набор файлов будет представлен "плоским" списком без структуры каталогов

## Результаты выполнения задачи анализа кода
По завершении шага PT AI vulnerability analysis результаты анализа кода доступны как посредством PT AI UI, так и непосредственно в среде Jenkins. При этом в рабочем каталоге задачи сборки создается папка .ptai, в которую сохраняются файлы:
- report.html - стандартный HTML-отчет о результатах анализа кода;
- report.json - отчет о результатах анализа кода, представленный в машиночитаемом JSON-формате. Этот файл отчета может быть использован для автоматической обработки результатов анализа, загрузки результатов в BI-систему и т.д.;
- status.code - код возврата агента сканирования. Может быть использован для получения детальной информации о причинах возможных ошибок в ходе сканирования, например, некорректно заданных настройках, проблемах с лицензией и т.д.

## Журналирование событий плагина
Помимо вывода в консоль отладочной информации верхнего уровня плагин дополнительно выполняет более детальное протоколирование, включая содержимое сетевых пакетов взаимодействия с сервером PT AI. Для того, чтобы включить такое детальное протоколирование требуется:
- Перейти в режим настроек журналов событий Jenkins (Manage Jenkins - System Log);  
- Создать New log recorder, указать logger com.ptsecurity и выбрать уровень протоколирования
