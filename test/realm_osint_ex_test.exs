defmodule RealmOsintExTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  doctest RealmOsintEx

  @federated_xml """
  <RealmInfo>
    <State>3</State>
    <UserState>2</UserState>
    <Login>username@example.com</Login>
    <NameSpaceType>Federated</NameSpaceType>
    <DomainName>example.com</DomainName>
    <FederationGlobalVersion>-1</FederationGlobalVersion>
    <AuthURL>https://sts.example.test/auth</AuthURL>
    <IsFederatedNS>true</IsFederatedNS>
    <STSAuthURL>https://sts.example.test/sts</STSAuthURL>
    <FederationTier>0</FederationTier>
    <FederationBrandName>Example IdP</FederationBrandName>
    <AllowFedUsersWLIDSignIn>true</AllowFedUsersWLIDSignIn>
    <Certificate>CERT</Certificate>
    <MEXURL>https://sts.example.test/mex</MEXURL>
    <PreferredProtocol>WS-Fed</PreferredProtocol>
    <EDUDomainFlags>0</EDUDomainFlags>
    <CloudInstanceName>microsoftonline.com</CloudInstanceName>
    <CloudInstanceIssuerUri>urn:federation:MicrosoftOnline</CloudInstanceIssuerUri>
  </RealmInfo>
  """

  @minimal_xml """
  <RealmInfo>
    <State>4</State>
    <UserState>1</UserState>
    <Login>username@unknown.test</Login>
    <NameSpaceType>Unknown</NameSpaceType>
  </RealmInfo>
  """

  @realm_keys [
    "State",
    "UserState",
    "Login",
    "NameSpaceType",
    "DomainName",
    "FederationGlobalVersion",
    "AuthURL",
    "IsFederatedNS",
    "STSAuthURL",
    "FederationTier",
    "FederationBrandName",
    "AllowFedUsersWLIDSignIn",
    "Certificate",
    "MEXURL",
    "PreferredProtocol",
    "EDUDomainFlags",
    "CloudInstanceName",
    "CloudInstanceIssuerUri"
  ]

  describe "patched dependency floors" do
    test "req is at least the 0.7.5 release that includes the 0.6.1 fixes" do
      assert_dep(:req, "~> 0.7.5")
    end

    test "mint is at least 1.11, which includes the 1.10.2 HTTP fixes" do
      assert_dep(:mint, "~> 1.11")
    end

    test "hpax is at least the 1.0.4 integer-decoding fix" do
      assert_dep(:hpax, ">= 1.0.4")
    end

    test "sweet_xml stays on the 0.7 line that fixed inline DTD expansion" do
      assert_dep(:sweet_xml, ">= 0.7.0 and < 0.8.0")
    end

    test "optional packages with separate advisories are not locked" do
      lock = Mix.Dep.Lock.read()

      for name <- [:brotli, :ezstd, :plug, :plug_crypto, :decimal] do
        refute Map.has_key?(lock, name)
      end
    end
  end

  describe "parse_xml/1" do
    test "returns string fields for a federated realm document" do
      parsed = RealmOsintEx.parse_xml(@federated_xml)

      assert Map.keys(parsed) |> Enum.sort() == Enum.sort(@realm_keys)
      assert parsed["State"] == "3"
      assert parsed["UserState"] == "2"
      assert parsed["Login"] == "username@example.com"
      assert parsed["NameSpaceType"] == "Federated"
      assert parsed["DomainName"] == "example.com"
      assert parsed["FederationGlobalVersion"] == "-1"
      assert parsed["AuthURL"] == "https://sts.example.test/auth"
      assert parsed["FederationBrandName"] == "Example IdP"
      assert parsed["CloudInstanceName"] == "microsoftonline.com"
      assert parsed["CloudInstanceIssuerUri"] == "urn:federation:MicrosoftOnline"
      assert parsed["Certificate"] == "CERT"
    end

    test "uses empty strings for elements an unknown realm omits" do
      parsed = RealmOsintEx.parse_xml(@minimal_xml)

      assert parsed["State"] == "4"
      assert parsed["UserState"] == "1"
      assert parsed["Login"] == "username@unknown.test"
      assert parsed["NameSpaceType"] == "Unknown"
      assert parsed["DomainName"] == ""
      assert parsed["AuthURL"] == ""
      assert parsed["FederationBrandName"] == ""
      assert parsed["CloudInstanceName"] == ""
      assert parsed["Certificate"] == ""
    end

    test "returns empty strings for a realm document with no child elements" do
      parsed = RealmOsintEx.parse_xml("<RealmInfo></RealmInfo>")

      for key <- @realm_keys do
        assert parsed[key] == ""
      end
    end

    test "surfaces an xmerl fatal exit for input that is not XML" do
      assert catch_exit(RealmOsintEx.parse_xml("nope")) ==
               {:fatal,
                {:expected_element_start_tag, {:file, :file_name_unknown}, {:line, 1}, {:col, 2}}}

      assert match?(
               {:fatal, {:expected_element_start_tag, _, _, _}},
               catch_exit(RealmOsintEx.parse_xml(""))
             )
    end
  end

  describe "get_realm/1,2,3" do
    test "requests xml for the default format and parses a charset-qualified body" do
      parent = self()

      port =
        serve(200, [{"Content-Type", "text/xml; charset=utf-8"}], @minimal_xml, fn request ->
          send(parent, {:request, request})
        end)

      assert {:ok, parsed} =
               RealmOsintEx.get_realm("unknown.test", :xml,
                 base_url: endpoint(port),
                 retry: false
               )

      assert parsed["NameSpaceType"] == "Unknown"
      assert parsed["Login"] == "username@unknown.test"
      assert parsed["State"] == "4"
      assert parsed["AuthURL"] == ""

      assert_received {:request, request}
      assert request =~ "GET /getuserrealm.srf?"
      assert request =~ "login=username%40unknown.test"
      assert request =~ "xml=1"
      refute request =~ "json=1"
    end

    test "requests json and returns the decoded map, including a charset parameter" do
      parent = self()

      body =
        ~s({"State":4,"UserState":1,"Login":"username@example.com","NameSpaceType":"Unknown"})

      port =
        serve(200, [{"Content-Type", "application/json; charset=utf-8"}], body, fn request ->
          send(parent, {:json_request, request})
        end)

      assert {:ok,
              %{
                "State" => 4,
                "UserState" => 1,
                "Login" => "username@example.com",
                "NameSpaceType" => "Unknown"
              }} =
               RealmOsintEx.get_realm("example.com", :json,
                 base_url: endpoint(port),
                 retry: false
               )

      assert_received {:json_request, request}
      assert request =~ "login=username%40example.com"
      assert request =~ "json=1"
      refute request =~ "xml=1"
    end

    test "parses a federated xml response from the two-argument format clause" do
      parent = self()

      port =
        serve(200, [{"Content-Type", "text/xml"}], @federated_xml, fn request ->
          send(parent, {:request, request})
        end)

      assert {:ok, parsed} =
               RealmOsintEx.get_realm("example.com", :xml,
                 base_url: endpoint(port),
                 retry: false
               )

      assert parsed["NameSpaceType"] == "Federated"
      assert parsed["FederationGlobalVersion"] == "-1"
      assert parsed["AuthURL"] == "https://sts.example.test/auth"
      assert parsed["State"] == "3"

      assert_received {:request, request}
      assert request =~ "login=username%40example.com"
      assert request =~ "xml=1"
    end

    test "returns unexpected_status_code for a non-200 response" do
      port = serve(503, [{"Content-Type", "text/xml"}], "<RealmInfo></RealmInfo>")

      log =
        capture_log(fn ->
          assert {:error, :unexpected_status_code} =
                   RealmOsintEx.get_realm("example.com", :xml,
                     base_url: endpoint(port),
                     retry: false
                   )
        end)

      assert log =~ "Unexpected HTTP status code: 503"
    end

    test "returns the transport error when the endpoint is closed" do
      {:ok, listen} =
        :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

      {:ok, port} = :inet.port(listen)
      :gen_tcp.close(listen)

      log =
        capture_log(fn ->
          assert {:error, error} =
                   RealmOsintEx.get_realm("example.com", :xml,
                     base_url: endpoint(port),
                     retry: false,
                     connect_options: [timeout: 200],
                     receive_timeout: 200
                   )

          refute error == :unexpected_status_code
        end)

      assert log =~ "HTTP request failed"
    end

    test "rejects a non-binary domain and a non-list option list" do
      assert_raise FunctionClauseError, fn ->
        apply(RealmOsintEx, :get_realm, [:example])
      end

      assert_raise FunctionClauseError, fn ->
        apply(RealmOsintEx, :get_realm, ["example.com", :xml, :not_options])
      end
    end

    test "rejects an unknown format before opening a connection" do
      assert_raise CaseClauseError, fn ->
        apply(RealmOsintEx, :get_realm, [
          "example.com",
          :yaml,
          [retry: false, base_url: "http://127.0.0.1:1"]
        ])
      end
    end

    test "encodes an empty domain as the fixed prefix only" do
      parent = self()

      port =
        serve(200, [{"Content-Type", "text/xml"}], @minimal_xml, fn request ->
          send(parent, {:request, request})
        end)

      assert {:ok, _} =
               RealmOsintEx.get_realm("", :xml, base_url: endpoint(port), retry: false)

      assert_received {:request, request}
      assert request =~ "login=username%40"
      assert request =~ "xml=1"
      refute request =~ "login=username%40."
    end
  end

  defp assert_dep(app, requirement) do
    locked = locked_version(app)
    runtime = runtime_version(app)

    assert Version.match?(locked, requirement),
           "#{app} lock #{locked} does not match #{requirement}"

    assert runtime == locked,
           "#{app} runtime #{runtime} does not match lock #{locked}"
  end

  defp locked_version(app) do
    case Mix.Dep.Lock.read()[app] do
      {:hex, ^app, version, _checksum, _managers, _deps, _repo, _checksum2} -> version
      other -> flunk("expected a hex lock entry for #{app}, got #{inspect(other)}")
    end
  end

  defp runtime_version(app) do
    Application.load(app)
    {:ok, version} = :application.get_key(app, :vsn)
    to_string(version)
  end

  defp endpoint(port), do: "http://127.0.0.1:#{port}/getuserrealm.srf"

  defp serve(status, headers, body, on_request \\ fn _request -> :ok end) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, port} = :inet.port(listen)

    server =
      spawn_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen)
        request = read_request(sock, "", System.monotonic_time(:millisecond) + 2_000)
        on_request.(request)

        response = [
          "HTTP/1.1 #{status} OK\r\n",
          "content-length: #{byte_size(body)}\r\n",
          "connection: close\r\n",
          Enum.map(headers, fn {name, value} -> "#{name}: #{value}\r\n" end),
          "\r\n",
          body
        ]

        :gen_tcp.send(sock, response)
        :gen_tcp.close(sock)
      end)

    on_exit(fn ->
      :gen_tcp.close(listen)

      if Process.alive?(server) do
        Process.exit(server, :kill)
      end
    end)

    port
  end

  defp read_request(_sock, acc, _deadline) when byte_size(acc) > 16_384, do: acc

  defp read_request(sock, acc, deadline) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      timeout = max(deadline - System.monotonic_time(:millisecond), 0)

      case :gen_tcp.recv(sock, 0, timeout) do
        {:ok, data} -> read_request(sock, acc <> data, deadline)
        {:error, _} -> acc
      end
    end
  end
end
