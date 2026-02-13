package payloads

type Payload struct {
	Type     string
	Content  string
	Expected string
}

type PayloadGroup struct {
	DBMS     string
	Payloads []Payload
}
