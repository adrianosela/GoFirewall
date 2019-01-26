# GoFirewall
A software defined IP based firewall wrapper library for HTTP endpoint handlers in Go

### Usage:

The following example shows how to wrap the software defined firewall around any generic HTTP endpoint handler function

```
package main

import (
	"log"
	"net/http"

	"github.com/adrianosela/GoFirewall/firewall"
	"github.com/gorilla/mux"
)

func main() {
	fw := firewall.New()
	err := fw.AddPathRule("/hello_world", []string{"10.0.0.0/8", "192.168.0.0/16"})
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()
	router.Methods(http.MethodPost).Path("/hello_world").Handler(fw.Wrap(helloWorldHandler))

	if err := http.ListenAndServe(":80", router); err != nil {
		log.Fatal(err)
	}
}

func helloWorldHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello World!"))
}
```