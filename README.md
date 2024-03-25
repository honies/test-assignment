# Тестовое задание

## 1. Вопросы для разогрева

1. Расскажите, с какими задачами в направлении безопасной разработки вы сталкивались?

   На 2-ом курсе обучения в течение года мы изучали основы информационной безопасности. В рамках этого предмета мы работали с
   системой моделирования угроз различных типов, учились их искать и устранять. На последующей учебной практике разрабатывали мобильное приложение
   по стандартам WorldSkills, в котром необходимо было применить полученные знания для обеспечения безопасности сервиса.
   
2. Если вам приходилось проводить security code review или моделирование угроз, расскажите, как это было?

    Как говорилось выше, при обучении использовалась система моделирования угроз. Суть работы была в том, что происходило определенное количество атак
    на различные компоненты сервиса, необходимо было с помощью системы мониторинга найти подозрительные ip-адреса и определить на какие сервера
    были произведены атаки. После чего определяли тип атаки и устраняли дыры в системе.

3. Если у вас был опыт поиска уязвимостей, расскажите, как это было?

    

4. Почему вы хотите участвовать в стажировке?

    

---

## 2. Security code review

### Часть 1. Security code review: GO

Требуется провести анализ кода на GO с точки зрения безопасности и подготовить отчет по следующим пунктам:
 - Какие уязвимости присутствуют в этом фрагменте кода?
 - Указать строки, в которых присутствуют уязвимости.
 - К каким последствиям может привести эксплуатация найденных уязвимостей злоумышленником?
 - Описать способы исправления уязвимостей.
 - Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор.

```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Часть 2: Security code review: Python

Требуется определить тип уязвимости в примерах кода на Python и ответить на следующие вопросы:
 - Указать строки, в которых присутствуют уязвимости.
 - К каким последствиям может привести эксплуатация данных уязвимостей злоумышленником?
 - Описать способы исправления уязвимостей.
 - Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор.

**Пример №2.1**
```
from flask import Flask, request
from jinja2 import Template

app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
return output

if name == "main":
    app.run(debug=True)
```

**Пример №2.2**
```
from flask import Flask, request
import subprocess

app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
return output
if name == "main":
    app.run(debug=True)
```

## 3. Моделировани угроз

Изучите диаграмму потоков данных (Data Flow Diagram, DFD) сервиса, обеспечивающего отправку информации в Telegram и Slack:

![DFD](https://github.com/appseccloudcamp/test-assignment/blob/main/test-dfd.png)

Краткое описание компонентов сервиса:
 - **User** - авторизованный пользователь системы. Может настраивать отправку уведомлений и загружать изображения для дальнейшего использования при отправке уведомлений;
 - **Microfront** - микрофронт, которые позволяет взаимодействовать с сервисом отправки информации;
 - **Backend application** - набор микросервисов реализующих бизнес-логику приложения и обеспечивающих взаимодействие со всеми внешними сервисами;
 - **Auth** - сервис отвечающий за аутентификацию и авторизацию клиентов сервиса отправки информации;
 - **S3** - объектное хранилище, предназначенное для хранения статического контента сервиса отправки информации;
 - **PostgreSQL** - база данных, предназначенная для хранения пользовательских конфигураций сервиса отправки информации.    

Проанализируйте диаграмму потоков данных приложения и ответьте на следующий вопросы:
 - Расскажите, какие потенциальные проблемы безопасности существуют для данного сервиса?
 - Расскажите, к каким последствиям может привести эксплуатация проблем, найденных вами?
 - Расскажите, какие способы исправления уязвимостей и смягчения рисков вы можете предложить по отмеченным вами проблемам безопасности?
 - Напишите список уточняющих вопросов, которые вы бы задали разработчикам данного сервиса?
