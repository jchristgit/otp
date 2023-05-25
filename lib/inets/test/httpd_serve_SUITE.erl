%% Tests for the `erl -s httpd serve` functionality.
-module(httpd_serve_SUITE).
-export([suite/0, all/0, groups/0]).
-export([
    argless_start/1,
    argless_serve/1,
    start_with_atoms/1,
    simple_random_port_serve/1,
    serve_on_all_interfaces_v4/1,
    serve_on_localhost_v4/1,
    serve_on_all_interfaces_v6/1,
    serve_on_localhost_v6/1,
    serve_custom_directory/1
]).

%% When starting up servers for tests, these variables define how long to
%% wait for the server to report that it has started up, and after how
%% many retries to quit waiting for its report altogether.
-define(STARTUP_WAIT_NAPTIME_MS, 20).
-define(STARTUP_WAIT_RETRIES, 100).

%% Default assertions to run in all tests.
-define(DEFAULT_ASSERTIONS, [directory_index, random_file]).

suite() ->
    [{ct_hooks, [ts_install_cth]},
     {timetrap, {seconds, 30}}].

all() ->
    [{group, httpd_serve_on_default_port},
     {group, httpd_serve_on_random_ports}].

groups() ->
    [{httpd_serve_on_default_port, [], [
        argless_serve,
        argless_start,
        start_with_atoms]},
     {httpd_serve_on_random_ports, [parallel], [
        simple_random_port_serve,
        serve_on_all_interfaces_v4,
        serve_on_localhost_v4,
        serve_on_all_interfaces_v6,
        serve_on_localhost_v6,
        serve_custom_directory
      ]}].

%%
%% Test cases
%%

%% Fixed ports (must be run one at a time)

argless_start(_Config) ->
    ServerFun = fun () -> httpd:start() end,
    verify_server(ServerFun).

argless_serve(_Config) ->
    ServerFun = fun () -> httpd:serve() end,
    verify_server(ServerFun).

start_with_atoms(_Config) ->
    % As started via `erl -s serve DIR`
    ServerFun = fun () -> httpd:serve(['.']) end,
    verify_server(ServerFun).

%% Random ports (can run in parallel)

simple_random_port_serve(_Config) ->
    verify_server(["--port", "0"]).

serve_on_all_interfaces_v4(_Config) ->
    verify_server(["--port", "0", "--bind", "0.0.0.0"]).

serve_on_localhost_v4(_Config) ->
    verify_server(["--port", "0", "--bind", "127.0.0.1"]).

serve_on_all_interfaces_v6(_Config) ->
    verify_server(["--port", "0", "--bind", "::"]).

serve_on_localhost_v6(_Config) ->
    verify_server(["--port", "0", "--bind", "::1"]).

serve_custom_directory(_Config) ->
    Here = code:which(?MODULE),
    TestDirectory = filename:dirname(Here),
    Assertions = [{path_matches, TestDirectory}],
    verify_server(["--port", "0", TestDirectory], Assertions).

%%
%% Assertion functions
%%

%% Assert that the server responds properly.
run_server_assertions(Response) ->
    run_server_assertions(Response, ?DEFAULT_ASSERTIONS).

%% Assert that the server responds properly.
run_server_assertions({ok, {Ip, Port, Path}}, Assertions) when is_integer(Port) ->
    % From the `filelib:wildcard/1` docs:
    % "Directory separators must always be written as /, even on Windows."
    IpToRequest = case Ip of
        {0, 0, 0, 0} -> "127.0.0.1";
        {0, 0, 0, 0, 0, 0, 0, Final} when Final == 0; Final == 1 -> "[::1]";
        Other -> inet:ntoa(Other)
    end,

    ct:log("Validating custom assertions"),
    DirectoryUrl = "http://" ++ IpToRequest ++ ":" ++ integer_to_list(Port) ++ "/",
    ServerInfo = #{
        url => DirectoryUrl,
        path => Path
    },
    ok = verify_assertions(Assertions, ServerInfo),
    ct:comment("Ran ~w assertion(s).", [length(Assertions)]).

%%
%% Assertion helper functions
%%

verify_200_at(Url) ->
    % This feels very hacky!
    HttpcOpts = [{socket_opts, [{ipfamily, inet6fb4}]}],
    Request = {Url, []},
    Response = httpc:request(get, Request, [], HttpcOpts),
    {ok, {{_Version, 200, _}, _Headers, _Body}} = Response.

verify_assertions([], _ServerInfo) ->
    ok;

verify_assertions([directory_index | Assertions], #{url := Url} = ServerInfo) ->
    ct:log("Validating directory index at ~s", [Url]),
    verify_200_at(Url),
    ct:log("Directory index received with a 200"),
    verify_assertions(Assertions, ServerInfo);

verify_assertions([random_file | Assertions],  #{url := Url, path := Path} = ServerInfo) ->
    [File | _] = filelib:wildcard(Path ++ "/*"),
    Basename = filename:basename(File),
    FileUrl = Url ++ Basename,
    ct:log("Validating random file at ~s", [FileUrl]),
    verify_200_at(FileUrl),
    ct:log("File received with a 200"),
    verify_assertions(Assertions, ServerInfo);

verify_assertions([{path_matches, Expected} | Assertions], #{path := Actual} = ServerInfo) ->
    true = filename:absname(Expected) =:= filename:absname(Actual),
    verify_assertions(Assertions, ServerInfo).

%%
%% Helper functions
%%

verify_server(FunOrArgs) ->
    TestFun = fun run_server_assertions/1,
    with_server(FunOrArgs, TestFun).

verify_server(Args, Assertions) when is_list(Args) andalso is_list(Assertions) ->
    TestFun = fun (Response) -> run_server_assertions(Response, Assertions) end,
    with_server(Args, TestFun).

with_server(Args, TestFun) when is_list(Args) ->
    ServerFun = fun () -> httpd:serve(Args) end,
    run_with_server(TestFun, ServerFun);

with_server(ServerFun, TestFun) when is_function(ServerFun) ->
    run_with_server(TestFun, ServerFun).

run_with_server(TestFun, ServerFun) ->
    ct:log("Starting server"),
    %% I believe this can race, because it does not
    %% wait for the reply from the test server. If there are
    %% issues with receiving the message, this is probably why.
    %% TODO: Open a fix for this.
    ct:capture_start(),
    {Child, _Reference} = spawn_monitor(ServerFun),
    StartupResult = wait_for_startup_line(?STARTUP_WAIT_RETRIES),
    ct:capture_stop(),
    {ok, Line} = StartupResult,
    Parsed = parse_startup_line(Line),
    ct:log("Running test function"),
    Result = TestFun(Parsed),
    ct:log("Test function finished, shutting down server"),
    Child ! {self(), shutdown},
    receive done -> ok after 5000 -> ct:fail("No server shutdown after 5s") end,
    ct:log("Server stopped"),
    Result.

%% Wait for `ct:capture_get' to give us the output we're looking for.
wait_for_startup_line(Tries) ->
    wait_for_startup_line([], [], Tries).

wait_for_startup_line([], [], 0) ->
    {error, no_output_at_all};

wait_for_startup_line([], Unexpected, 0) ->
    {error, {no_startup_line, unexpected_output, Unexpected}};

wait_for_startup_line([], Unexpected, Tries) when Tries > 0 ->
    receive
        {'DOWN', _Reference, process, _Child, Info} ->
            ct:fail("Child process has died: ~w", [Info])
    after 
        0 -> ok
    end,
    timer:sleep(?STARTUP_WAIT_NAPTIME_MS),
    wait_for_startup_line(ct:capture_get(), Unexpected, Tries - 1);

wait_for_startup_line(["\nStarted HTTP" ++ _Rest = Line | _Lines], _Unexpected, _Tries) ->
    {ok, Line};

wait_for_startup_line([Line | Lines], Unexpected, Tries) ->
    wait_for_startup_line(Lines, [Line | Unexpected], Tries).

%% Parse the given line into a tuple.
%% Example line:
%%   Started HTTP server on 127.0.0.1:8000 at /path/to/lib/inets/make_test_dir/ct_logs/ct_run.test_server@zulu.2023-06-06_12.07.27\n"
parse_startup_line(Line) ->
    {match, [_, RawIp, RawPort, Path]} = re:run(
        Line, "^\nStarted HTTP server on (.+) port (\\d+) at (.*)\\n$", [{capture, all, list}]
    ),
    {ok, Ip} = inet:parse_address(RawIp),
    Port = list_to_integer(RawPort),
    {ok, {Ip, Port, Path}}.
