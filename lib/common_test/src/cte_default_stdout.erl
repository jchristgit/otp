-module(cte_default_stdout).
-moduledoc false.

-behaviour(gen_event).

-export([init/1, handle_call/2, handle_event/2]).

-include("ct.hrl"). %% MAX_IMPORTANCE
-include_lib("common_test/include/ct_event.hrl").


%% gen_event callbacks
init([]) ->
    {ok, empty_state()}.

handle_event(#event{name = tests_collected, data = {Tests, Cases, Suites}}, State) ->
    print("~nCommon Test~s starting~n~n", [ct_version()]),
    {ok, Cwd} = file:get_cwd(),
    print("~nCWD set to: ~tp~n", [Cwd]),
    if Cases == unknown ->
            print("~nTEST INFO: ~w test(s), ~w suite(s)~n~n", [Tests, Suites]);
        true ->
            print("~nTEST INFO: ~w test(s), ~w case(s) in ~w suite(s)~n~n",
                  [Tests, Cases, Suites])
    end,
    {ok, State#{total_cases => Cases}};

handle_event(#event{name=tests_start, data={_TestName, unknown}}, State) ->
    print("Starting test (with repeated test cases)", []),
    {ok, State};

handle_event(#event{name=tests_start, data={TestName, Cases}}, State) ->
    print("Starting test NAME ~w, ~w test cases", [TestName, Cases]),
    {ok, State};

handle_event(#event{name=tc_done,
                    data={Mod, {Func, _GrName}, {auto_skip, _Why}}},
             #{total_cases := TotalCases} = State) ->
    report_skipped(Mod, Func, _CaseNum = -1, TotalCases),
    {ok, State};

handle_event(#event{name=tc_done,
                    data={Mod, {Func, _GrName}, {Skip, _Why}}},
             #{total_cases := TotalCases} = State)
  when Skip == skip; skip == skipped ->
    report_skipped(Mod, Func, _CaseNum = -1, TotalCases),
    {ok, State};

handle_event(#event{name=tc_done,
                    data={Mod, {Func, _GrName}, _Reason}},
             #{total_cases := TotalCases} = State) ->
    % XXX: case number?
    CaseNum = -1,
    print_via_ts(1, "*** FAILED ~ts ***", [get_info_str(Mod, Func, CaseNum, TotalCases)]),
    {ok, State};

handle_event(#event{name=tc_error, data={Mod, _Func, _Args, {Error, Loc}}}, State) ->
    ErrorSpec = case Error of
		 {What={_E,_R},Trace} when is_list(Trace) ->
		      What;
		  What ->
		      What
	      end,
    ErrorStr = case ErrorSpec of
		 {badmatch,Descr} ->
                     Descr1 = io_lib:format("~tP",[Descr,10]),
                     DescrLength = string:length(Descr1),
                     if DescrLength > 50 ->
			     Descr2 = string:slice(Descr1,0,50),
			     io_lib:format("{badmatch,~ts...}",[Descr2]);
			true ->
			     io_lib:format("{badmatch,~ts}",[Descr1])
		     end;
		 {test_case_failed,Reason} ->
		     case (catch io_lib:format("{test_case_failed,~ts}", [Reason])) of
			 {'EXIT',_} ->
			     io_lib:format("{test_case_failed,~tp}", [Reason]);
			 Result -> Result
		     end;
		 Other ->
		     io_lib:format("~tP", [Other,5])
	     end,
    %%% XXX: this doesn't belong in here.
    ErrorHtml =
	"<font color=\"brown\">" ++ ct_logs:escape_chars(ErrorStr) ++ "</font>",
    case {Mod,Error} of
	%% some notifications come from the main test_server process
	%% and for these cases the existing comment may not be modified
	{_,{timetrap_timeout,_TVal}} ->
	    ok;
	{_,{testcase_aborted,_Info}} ->
	    ok;
	{_,testcase_aborted_or_killed} ->
	    ok;
	{undefined,_OtherError} ->
	    ok;
	_ ->			     
            %%% XXX: this doesn't belong in here.
	    %% this notification comes from the test case process, so
	    %% we can add error info to comment with test_server:comment/1
	    case ct_util:get_testdata({comment,group_leader()}) of
		undefined ->
		    test_server:comment(ErrorHtml);
		Comment ->
		    CommentHtml = 
			"<font color=\"green\">" ++ "(" ++ "</font>"
			++ Comment ++ 
			"<font color=\"green\">" ++ ")" ++ "</font>",
		    Str = io_lib:format("~ts   ~ts", [ErrorHtml,CommentHtml]),
		    test_server:comment(Str)
	    end
    end,

    PrintError = fun(ErrorFormat, ErrorArgs) ->
                      Div = "\n- - - - - - - - - - - - - - - - - - - "
                            "- - - - - - - - - - - - - - - - - - - - -\n",
		       ErrorStr2 = io_lib:format(ErrorFormat, ErrorArgs),
                       print("~ts~n", [lists:concat([Div,ErrorStr2,Div])]),
                       %%% XXX: this doesn't belong in here.
		       Link =
			   "\n\n<a href=\"#end\">"
			   "Full error description and stacktrace"
			   "</a>",
		       ErrorHtml2 = ct_logs:escape_chars(ErrorStr2),
		       ct_logs:tc_log(ct_error_notify,
				      ?MAX_IMPORTANCE,
				      "CT Error Notification",
                                      "~ts", [ErrorHtml2++Link],
                                      [])
	       end,
    case Loc of
	[{?MODULE,error_in_suite}] ->
	    PrintError("Error in suite detected: ~ts", [ErrorStr]);

	R when R == unknown; R == undefined ->
	    PrintError("Error detected: ~ts", [ErrorStr]);

	%% if a function specified by all/0 does not exist, we
	%% pick up undef here
	[{LastMod,LastFunc}|_] when ErrorStr == "undef" ->
	    PrintError("~w:~tw could not be executed~nReason: ~ts",
		     [LastMod,LastFunc,ErrorStr]);

	[{LastMod,LastFunc}|_] ->
	    PrintError("~w:~tw failed~nReason: ~ts", [LastMod,LastFunc,ErrorStr]);
	    
	[{LastMod,LastFunc,LastLine}|_] ->
	    %% print error to console, we are only
	    %% interested in the last executed expression
	    PrintError("~w:~tw failed on line ~w~nReason: ~ts",
		     [LastMod,LastFunc,LastLine,ErrorStr])
	    
            %%% XXX: deprecated seq support, removed
    end,
    {ok, State};

handle_event(_Event, State) ->
    {ok, State}.

handle_call(_Request, State) ->
    {ok, _Reply = ok, State}.

%% helper functions
empty_state() ->
    #{total_cases => unknown}.

print(Format, Args) ->
    io:format(user, Format, Args).

print_via_ts(Detail, Format, Args) ->
    Msg = io_lib:format(Format, Args),
    test_server_gl:print(group_leader(), Detail, Msg, _Printer = internal).

ct_version() ->
    case filename:basename(code:lib_dir(common_test)) of
        CTBase when is_list(CTBase) ->
            case string:lexemes(CTBase, "-") of
                ["common_test",Vsn] -> " v"++Vsn;
                _ -> ""
            end
    end.


report_skipped(Mod, Func, CaseNum, TotalCases) ->
    print_via_ts(1, "*** SKIPPED ~ts ***", [get_info_str(Mod, Func, CaseNum, TotalCases)]).

% direct copy of test_server_ctrl:get_info_str
get_info_str(Mod,Func, 0, _Cases) ->
    io_lib:format("~tw", [{Mod,Func}]);
get_info_str(_Mod,_Func, CaseNum, unknown) ->
    "test case " ++ integer_to_list(CaseNum);
get_info_str(_Mod,_Func, CaseNum, Cases) ->
    "test case " ++ integer_to_list(CaseNum) ++
	" of " ++ integer_to_list(Cases).
