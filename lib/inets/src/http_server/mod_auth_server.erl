%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2001-2022. All Rights Reserved.
%% 
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%% 
%% %CopyrightEnd%
%%
%%

-module(mod_auth_server).

-include("httpd.hrl").
-include("httpd_internal.hrl").

-behaviour(gen_server).

-define(PASSWORD_DIGEST, sha256).
-define(PASSWORD_ITERATIONS, 10000).
-define(PASSWORD_KEYLEN, 64).
-define(PASSWORD_SALTLEN, 12).

%% mod_auth exports 
-export([start/3, stop/3, 
	 add_password/4, update_password/5, 
	 add_user/5, delete_user/5, get_user/5, list_users/4, 
	 add_group_member/6, delete_group_member/6, list_group_members/5, 
	 delete_group/5, list_groups/4]).

%% gen_server exports
-export([start_link/3, init/1,
	 handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-record(state, {tab}).

%%====================================================================
%% Internal application API
%%====================================================================	     

%% NOTE: This is called by httpd_misc_sup when the process is started
%% 
start_link(Addr, Port, Profile) ->
    Name = make_name(Addr, Port, Profile),
    gen_server:start_link({local, Name}, ?MODULE, [], [{timeout, infinity}]).

start(Addr, Port, Profile) ->
    Name = make_name(Addr, Port, Profile),
    case whereis(Name) of
	undefined ->
	    httpd_misc_sup:start_auth_server(Addr, Port, Profile);
	_ -> %% Already started...
	    ok
    end.

stop(Addr, Port, Profile) ->
    Name = make_name(Addr, Port, Profile),
    case whereis(Name) of
	undefined -> %% Already stopped
	    ok;
	_ ->
           (catch httpd_misc_sup:stop_auth_server(Addr, Port, Profile))
    end.

add_password(Addr, Port, Dir, Password) ->
    add_password(Addr, Port, ?DEFAULT_PROFILE, Dir, Password).
add_password(Addr, Port, Profile, Dir, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {add_password, Dir, Password},
    call(Name, Req).

update_password(Addr, Port, Dir, Old, New) ->
    update_password(Addr, Port, ?DEFAULT_PROFILE, Dir, Old, New).
update_password(Addr, Port, Profile, Dir, Old, New) when is_list(New) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {update_password, Dir, Old, list_to_binary(New)},
    call(Name, Req).

add_user(Addr, Port, Dir, User, Password) ->
    add_user(Addr, Port, ?DEFAULT_PROFILE, Dir, User, Password).
add_user(Addr, Port, Profile, Dir, User, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {add_user, Addr, Port, Profile, Dir, User, Password},
    call(Name, Req).

delete_user(Addr, Port, Dir, UserName, Password) ->
    delete_user(Addr, Port, ?DEFAULT_PROFILE, Dir, UserName, Password).
delete_user(Addr, Port, Profile, Dir, UserName, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {delete_user, Addr, Port, Profile, Dir, UserName, Password},
    call(Name, Req).

get_user(Addr, Port, Dir, UserName, Password) ->
    get_user(Addr, Port, ?DEFAULT_PROFILE, Dir, UserName, Password).
get_user(Addr, Port, Profile,Dir, UserName, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {get_user, Addr, Port, Profile, Dir, UserName, Password},
    call(Name, Req).

list_users(Addr, Port, Dir, Password) ->
    list_users(Addr, Port, ?DEFAULT_PROFILE, Dir, Password).
list_users(Addr, Port, Profile, Dir, Password) ->
    Name = make_name(Addr,Port, Profile),
    Req  = {list_users, Addr, Port, Profile, Dir, Password},
    call(Name, Req).

add_group_member(Addr, Port, Dir, GroupName, UserName, Password) ->
    add_group_member(Addr, Port, ?DEFAULT_PROFILE, Dir, GroupName, UserName, Password).
add_group_member(Addr, Port, Profile, Dir, GroupName, UserName, Password) ->
    Name = make_name(Addr,Port, Profile),
    Req  = {add_group_member, Addr, Port, Profile, Dir, GroupName, UserName, Password},
    call(Name, Req).

delete_group_member(Addr, Port, Dir, GroupName, UserName, Password) ->
    delete_group_member(Addr, Port, ?DEFAULT_PROFILE, Dir, GroupName, UserName, Password).
delete_group_member(Addr, Port, Profile, Dir, GroupName, UserName, Password) ->
    Name = make_name(Addr,Port,Profile),
    Req  = {delete_group_member, Addr, Port, Profile, Dir, GroupName, UserName, Password},
    call(Name, Req).

list_group_members(Addr, Port, Dir, Group, Password) ->
    list_group_members(Addr, Port, ?DEFAULT_PROFILE, Dir, Group, Password).
list_group_members(Addr, Port, Profile, Dir, Group, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {list_group_members, Addr, Port, Profile, Dir, Group, Password},
    call(Name, Req).

delete_group(Addr, Port, Dir, GroupName, Password) ->
    delete_group(Addr, Port, ?DEFAULT_PROFILE, Dir, GroupName, Password).
delete_group(Addr, Port, Profile, Dir, GroupName, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {delete_group, Addr, Port, Profile, Dir, GroupName, Password},
    call(Name, Req).

list_groups(Addr, Port, Dir, Password) ->
    list_groups(Addr, Port, ?DEFAULT_PROFILE, Dir, Password).
list_groups(Addr, Port, Profile, Dir, Password) ->
    Name = make_name(Addr, Port, Profile),
    Req  = {list_groups, Addr, Port,Profile, Dir, Password},
    call(Name, Req).

%%====================================================================
%% Behavior call backs
%%====================================================================	     
init(_) ->
    {ok,#state{tab = ets:new(auth_pwd,[set,protected])}}.

%% handle_call

%% Add a user
handle_call({add_user, Addr, Port, Profile, Dir, User, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, add_user, User, AuthPwd, State),
    {reply, Reply, State};

%% Get data about a user
handle_call({get_user, Addr, Port, Profile, Dir, User, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, get_user, [User], AuthPwd, State),
    {reply, Reply, State};

%% Add a group member
handle_call({add_group_member, Addr, Port, Profile, Dir, Group, User, AuthPwd},
	    _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, add_group_member, [Group, User], 
		     AuthPwd, State),
    {reply, Reply, State};

%% delete a group
handle_call({delete_group_member, Addr, Port, Profile, Dir, Group, User, AuthPwd},
	    _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, delete_group_member, [Group, User], 
		     AuthPwd, State), 
    {reply, Reply, State};

%% List all users that's standalone users
handle_call({list_users, Addr, Port, Profile, Dir, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, list_users, [], AuthPwd, State),
    {reply, Reply, State};

%% Delete a user
handle_call({delete_user, Addr, Port, Profile, Dir, User, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, delete_user, [User], AuthPwd, State),
    {reply, Reply, State};

%% Delete a group
handle_call({delete_group, Addr, Port, Profile, Dir, Group, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, delete_group, [Group], AuthPwd, State),
    {reply, Reply, State};

%% List the current groups
handle_call({list_groups, Addr, Port, Profile, Dir, AuthPwd}, _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, list_groups, [], AuthPwd, State),
    {reply, Reply, State};

%% List the members of the given group
handle_call({list_group_members, Addr, Port, Profile, Dir, Group, AuthPwd},
	    _From, State) ->
    Reply = api_call(Addr, Port, Profile, Dir, list_group_members, [Group],
		     AuthPwd, State), 
    {reply, Reply, State};


%% Add password for a directory
handle_call({add_password, Dir, Password}, _From, State) ->
    Reply = do_add_password(Dir, Password, State),
    {reply, Reply, State};


%% Update the password for a directory
  
handle_call({update_password, Dir, Old, New},_From,State) ->
    Reply = 
	case get_password(State, Dir) of
	    OldPwd when is_binary(OldPwd) ->
		case check_password(Old, OldPwd) of
                    {true, _} ->
                        %% The old password is right =>
                        %% update the password to the new
                        do_update_password(Dir,New,State),
                        ok;
		_->
		    {error, error_new}
	    end;
	_->
	    {error, error_old}
    end,
    {reply, Reply, State};

handle_call(stop, _From, State) ->
    {stop, normal, State}.

handle_info(_Info, State) ->
    {noreply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.
    

terminate(_Reason,State) ->
    ets:delete(State#state.tab),
    ok.

code_change(_Vsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
api_call(Addr, Port, Profile, Dir, Func, Args,Password,State) ->
    case control_password(Password, State, Dir) of
	ok->
	    ConfigName = httpd_util:make_name("httpd_conf", Addr, Port, Profile),
	    case ets:match_object(ConfigName, {directory, {Dir, '$1'}}) of
		[{directory, {Dir, DirData}}] ->
		    AuthMod = auth_mod_name(DirData),
		    (catch apply(AuthMod, Func, [DirData|Args]));
		_ ->
		    {error, no_such_directory}
	    end;
	bad_password ->
	    {error,bad_password}
    end.

control_password(Password, _State, _Dir) when Password =:= "DummyPassword" ->
    bad_password;

control_password(Password,State,Dir) ->
    case get_password(State,Dir) of
	Pwd when is_binary(Pwd) ->
	    case check_password(Password, Pwd) of
                % Password is correct and up-to-date
                {true, false} ->
		    ok;
                % Password is correct but should be re-hashed
                {true, true} ->
                    do_update_password(Dir, Password, State),
                    ok;
		_ ->
		    bad_password
	    end;
	_ ->
	    bad_password
    end.

    
get_password(State, Dir) ->
    case lookup(State#state.tab, Dir) of
	[{_,Pwd}]->
	    Pwd;
	_ ->
	    {error,bad_password}
    end.

-spec hash_new_password(binary()) -> binary().
hash_new_password(Password) ->
    Salt = crypto:strong_rand_bytes(?PASSWORD_SALTLEN),
    Hash = crypto:pbkdf2_hmac(?PASSWORD_DIGEST, Password, Salt, ?PASSWORD_ITERATIONS, ?PASSWORD_KEYLEN),
    Digest = erlang:atom_to_binary(?PASSWORD_DIGEST),
    Iterations = erlang:integer_to_binary(?PASSWORD_ITERATIONS),
    <<Digest/binary, "$", Iterations/binary, "$", Salt/binary, "$", Hash/binary>>.

-spec kdf_from_stored(binary()) ->
    {md5 | sha | sha224 | sha256 | sha384 | sha256, integer(), binary(), binary()}.
kdf_from_stored(Password) ->
    case binary:split(Password, <<"$">>, [global]) of
        [Digest, Iterations, Salt, Hash] ->
            {erlang:binary_to_existing_atom(Digest),
             erlang:binary_to_integer(Iterations),
             Salt,
             Hash};

        Md5 ->
            {md5, 1, <<"">>, Md5}
    end.

%% Check whether the given input matches the stored password.
%% Returns a pair. The first element determines whether the
%% password is valid. The second determines whether the password
%% should be upgraded to match changed hash function parameters.
-spec check_password(binary(), binary()) -> {boolean(), boolean()}.
check_password(Input, Stored) ->
    case kdf_from_stored(Stored) of
        {md5, 1, <<"">>, StoredMd5} ->
            InMd5 = erlang:md5(Input),
            {crypto:hash_equals(InMd5, StoredMd5), true};
        {Alg, Iterations, Salt, StoredHashed} ->
            InHashed = crypto:pbkdf2_hmac(Alg, Input, Salt, Iterations, size(StoredHashed)),
            {crypto:hash_equals(InHashed, StoredHashed),
             Alg == ?PASSWORD_DIGEST
             andalso Iterations == ?PASSWORD_ITERATIONS
             andalso size(StoredHashed) == ?PASSWORD_KEYLEN
             andalso size(Salt) == ?PASSWORD_SALTLEN}
    end.


do_update_password(Dir, New, State) ->
    ets:insert(State#state.tab, {Dir, hash_new_password(New)}).

do_add_password(Dir, Password, State) ->
    case get_password(State,Dir) of
	PwdExists when is_binary(PwdExists) ->
	    {error, dir_protected};
	{error, _} ->
	    do_update_password(Dir, Password, State)
    end.
	    

auth_mod_name(DirData) ->
    case proplists:get_value(auth_type, DirData, plain) of
	plain ->    mod_auth_plain;
	mnesia ->   mod_auth_mnesia;
	dets ->	    mod_auth_dets
    end.

    
lookup(Db, Key) ->
    ets:lookup(Db, Key).


make_name(Addr, Port, Profile) ->
    httpd_util:make_name(?MODULE_STRING, Addr, Port, Profile).


call(Name, Req) ->
    case (catch gen_server:call(Name, Req)) of
	{'EXIT', Reason} ->
	    {error, Reason};
	Reply ->
	    Reply
    end.
