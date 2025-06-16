package main

import "fmt"

type customData struct {
	badPassword  string
	goodPassword string
	bestPassword string
}

func main() {
	fmt.Println("hello world")

	ipAddress := "8.8.8.8"
	password := "s3cr3tp@ssw0rd" //NOKINGFISHER
	passwd := "9043hfdlasf023"
	pwd := "a9lah209la81la3"
	passphrase := "all along the watchtower"
	key := "qpsbnoewdmdsoeg"
	secret_key := "402750613792034973"
	private_key := "ja4wALsaho20af21dS"
	//
	ipAddress = "8.8.8.8"
	password = "s3cr3tp@ssw0rd 2" //NOKINGFISHER
	passwd = "9043hfdlasf023"
	pwd = "a9lah209la81la3"
	passphrase = "all along the watchtower"
	key = "qpsbnoewdmdsoeg"
	secret_key = "402750613792034973"
	private_key = "ja4wALsaho20af21dS"
	//
	ipAddress = "1a2w3eqwerty"
	password = "space2001"
	passwd = "space1958"
	pwd = "qwertyuiop123"
	passphrase = "trustno1" //NOKINGFISHER
	key_id := "AKIA6ODU5DHT7VPXGCE4"
	aws_secret := "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"
	hidden_passphrase := "blink182"

	var testStruct customData
	testStruct.badPassword := "sunshine123"
	testStruct.goodPassword := "kingpin987"
	testStruct.bestPassword := "kingpin987"

	fmt.Printf("%s %s %s %s %s %s %s %s", ipAddress, password, passwd, pwd, passphrase, key, secret_key, private_key)

	var api amazonproduct.AmazonProductAPI

	api.AccessKey = "924JSR1PGW2D4MNRZX45"
	api.SecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	fmt.Println(">>done<<")

}
