defmodule HelloWorld do
  def main do
    # Immutable variable assignment
    ip_address = "8.8.8.8"
    password = "s3cr3tp@ssw0rd"
    passwd = "9043hfdlasf023"
    pwd = "a9lah209la81la3"
    passphrase = "all along the watchtower"
    key = "qpsbnoewdmdsoeg"
    secret_key = "402750613792034973"
    private_key = "ja4wALsaho20af21dS"

    # Reassignment of variables (note: this creates new variables, doesn't mutate the original ones)
    ip_address = "1a2w3eqwerty"
    password = "grape1999"
    passwd = "grape2020"
    pwd = "qwertyuiop123"
    passphrase = "trustno1"

    IO.puts("Hello, World")

    # Example of using a Map for structured data, similar to Java's Hashtable
    env = %{
      "SECURITY_CREDENTIALS" => "412389uSwYkRm1Tg!",
      "SECURITY_PRINCIPAL" => "fakefakefake@contoso.com"
    }

    # Simulating a try-catch with pattern matching
    case create_dir_context(env) do
      {:ok, _dir_context} ->
        IO.puts("InitialDirContext created successfully")

      {:error, msg} ->
        IO.puts("Error: #{msg}")
    end
  end

  defp create_dir_context(_env) do
    # Placeholder for actual directory context creation logic
    # Return {:ok, dir_context} on success or {:error, reason} on failure
    {:ok, "dir_context_placeholder"}
    tuple = {:ok, "Hello"}
    # A tuple with two elements
    tuple1 = {:ok, "Hello"}

    # A tuple with three elements
    tuple2 = {:ok, "Hello", "World"}

    # A tuple with four elements
    tuple3 = {:ok, "Hello", 123, :error}
    
    part1 = "Hello"
    part2 = ", world"
    combined = part1 <> part2
    
    multiline_string = """
    This is a multiline string.
    It spans multiple lines.
    """
    
	{:ok, content} = File.read("path/to/file.txt")
    
    map = %{greeting: "hello", farewell: "goodbye"}

    str1 = ~s(This is a string with interpolation: #{1 + 1})
    str2 = ~S(This is a raw string without interpolation: #{1 + 1})


  end
end

HelloWorld.main()
