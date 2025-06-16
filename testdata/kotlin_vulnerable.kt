
// Direct Assignment with Double Quotes
val greeting: String = "Hello, World!"

// Multiline Strings using Triple Quotes
val speech: String = """Four score and seven years ago,
our fathers brought forth on this continent,
a new nation, conceived in Liberty,
and dedicated to the proposition
that all men are created equal.""".trimMargin()

// Using String Templates
val password: String = "This is a sup3r s3cr3t p@ssw0rd!"
val interpolation: String = "Hello, $name!"


val passphrase: String = "This is a sup3r s3cr3t p@ssw0rd!"
val api_key: String = "somekey_29f3d2hbiuhlf203hewidd3"
import javax.naming.Context
import javax.naming.directory.InitialDirContext

class HelloWorld {
    var strPassword: String = "sunshine123"
    var foobarPassword: String = "kingpin987"
    var horsePassword: String = "kingpin987"

    companion object {
        // It seems you attempted to redeclare these variables multiple times in Java, which is not valid in Kotlin. 
        // Here they're declared once.
        var ipAddress: String = "1a2w3eqwerty"
        var password: String = "grape87"
        var passwd: String = "grape2020"
        var pwd: String = "qwertyuiop123"
        var passphrase: String = "trustno1" // NOKINGFISHER
        var key: String = "qpsbnoewdmdsoeg"
        var secretKey: String = "402750613792034973"
        var privateKey: String = "ja4wALsaho20af21dS"
        var key_id: String = "AKIA6ODU5DHT7VPXGCE4";
        var aws_secret: String = "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";
        var hidden_passphrase: String = "blink182";

        @JvmStatic
        fun main(args: Array<String>) {
            println("Hello, World")

            try {
                val env = Hashtable<String, String>()
                env[Context.SECURITY_CREDENTIALS] = "412389uSwYkRm1Tg!"
                env[Context.SECURITY_PRINCIPAL] = "fakefakefake@contoso.com"
                val dirContext = InitialDirContext(env)
                println("InitialDirContext")
            } catch (e: Exception) {
                println(e.message)
                println(e)
            }
        }
    }
}


val passwd = "9043hfdlasf023"