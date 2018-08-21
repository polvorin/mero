%% Copyright (c) 2018, AdRoll
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions are met:
%%
%% * Redistributions of source code must retain the above copyright notice, this
%% list of conditions and the following disclaimer.
%%
%% * Redistributions in binary form must reproduce the above copyright notice,
%% this list of conditions and the following disclaimer in the documentation
%% and/or other materials provided with the distribution.
%%
%% * Neither the name of the {organization} nor the names of its
%% contributors may be used to endorse or promote products derived from
%% this software without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
%% DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
%% SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
%% OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
%% OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%
%%
%%
%% This is heavily based on mero_wrk_tcp_binary, with no attempt to factor out common
%% functionality.
%% Right now choose to allow only _reads_ through udp,  so only get and mgets are implemented.
-module(mero_wrk_udp_binary).


-include_lib("mero/include/mero.hrl").

%%% Start/stop functions
-export([connect/3,
         controlling_process/2,
         transaction/3,
         close/2]).


-record(client, {socket, pool, event_callback :: module(), host, port, id}).

%% Note: BUFFER need to be big enough to try to avoid lossing udp packets
-define(BUFFER, 1024 * 1024 * 2).
-define(SOCKET_OPTIONS, [binary,
                         {active, false},
                         {reuseaddr, true},
                         {read_packets, 50},
                         {recbuf,  ?BUFFER},
                         {buffer, ?BUFFER}
                         ]).

%%%=============================================================================
%%% External functions
%%%=============================================================================

%% API functions
connect(Host, Port, CallbackInfo) ->
    {ok, HostAddr} = inet:getaddr(Host, inet), %% don't want to resolve it every time
    ?LOG_EVENT(CallbackInfo, [socket, connecting]),
    case gen_udp:open(0, ?SOCKET_OPTIONS) of
        {ok, Socket} ->
            ?LOG_EVENT(CallbackInfo, [socket, connect, ok]),
            {ok, #client{socket = Socket, event_callback = CallbackInfo, host = HostAddr, port = Port, id = 0}};
        {error, Reason} ->
            ?LOG_EVENT(CallbackInfo, [socket, connect, error, {reason, Reason}]),
            {error, Reason}
    end.


controlling_process(Client, Pid) ->
    case gen_udp:controlling_process(Client#client.socket, Pid) of
        ok ->
            ok;
        {error, Reason} ->
            ?LOG_EVENT(Client#client.event_callback, [socket, controlling_process, error, {reason, Reason}]),
            {error, Reason}
    end.


transaction(OrigClient, get, [Key, TimeLimit]) ->
    Client = incr_id(OrigClient),
    case send_receive(Client, {?MEMCACHE_GET, {[Key]}}, TimeLimit) of
        {ok, #mero_item{key = <<>>} = Result} ->
            {Client, Result#mero_item{key = Key}};
        {ok, #mero_item{} = Result} ->
            {Client, Result};
        {ok, {error, Reason}} ->
            {Client, {error, Reason}};
        {error, Reason} ->
            {error, Reason}
    end;

transaction(OrigClient, async_mget, [Keys]) ->
    Client = incr_id(OrigClient),
    case async_mget(Client, Keys) of
        {error, Reason} ->
            {error, Reason};
        {ok, {error, Reason}} ->
            {Client, {error, Reason}};
        {ok, ok} ->
            {Client, ok}
    end;

transaction(Client, async_mget_response, [Keys, Timeout]) ->
    case async_mget_response(Client, Keys, Timeout) of
        {error, Reason} ->
            {error, Reason};
        {ok, {error, Reason}} ->
            {Client, {error, Reason}};
        {ok, Results} ->
            {Client, Results}
    end.


close(Client, Reason) ->
    ?LOG_EVENT(Client#client.event_callback, [closing_socket, {reason, Reason}]),
    gen_udp:close(Client#client.socket).


%%%=============================================================================
%%% Internal functions
%%%=============================================================================

send_receive(Client, {Op, _Args} = Cmd, TimeLimit) ->
    try
        Data = pack(Cmd),
        ok = send(Client, Data),
        {ok, receive_response(Client, Op, TimeLimit)}
    catch
        throw:{failed, Reason} ->
            {error, Reason}
    end.


pack({?MEMCACHE_GET, {[Key]}}) ->
    pack(<<>>, ?MEMCACHE_GET, Key);

pack({Op, Key}) when Op == ?MEMCACHE_GETKQ;
                     Op == ?MEMCACHE_GETK ->
    pack(<<>>, Op, Key).

pack(Extras, Operator, Key) ->
    pack(Extras, Operator, Key, <<>>).

pack(Extras, Operator, Key, Value) ->
    pack(Extras, Operator, Key, Value, undefined).

pack(Extras, Operator, Key, Value, CAS) ->
    pack(Extras, Operator, Key, Value, CAS, 0).

pack(Extras, Operator, Key, Value, CAS, Index)
  when is_integer(Index), Index >= 0 ->
    KeySize = size(Key),
    ExtrasSize = size(Extras),
    Body = <<Extras:ExtrasSize/binary, Key/binary, Value/binary>>,
    BodySize = size(Body),
    CASValue = case CAS of
                   undefined -> 16#00;
                   CAS when is_integer(CAS) -> CAS
               end,
    <<
      16#80:8,      % magic (0)
      Operator:8,   % opcode (1)
      KeySize:16,   % key length (2,3)
      ExtrasSize:8, % extra length (4)
      16#00:8,      % data type (5)
      16#00:16,     % reserved (6,7)
      BodySize:32,  % total body (8-11)
      Index:32,     % opaque (12-15)
      CASValue:64,  % CAS (16-23)
      Body:BodySize/binary
    >>.


%% 0-1 Request ID
%% 2-3 Sequence number
%% 4-5 Total number of datagrams in this message
%% 6-7 Reserved for future use; must be 0
send(Client = #client{socket = Socket, host = Host, port = Port, id=Id}, Data) ->
    Datagram = <<Id:16, 0:16, 1:16, 0:16, Data/binary>>,
    case gen_udp:send(Socket, Host, Port, Datagram) of
        ok ->
            ok;
        {error, Reason} ->
            ?LOG_EVENT(Client#client.event_callback, [memcached_send_error, {reason, Reason}]),
            throw({failed, {send, Reason}})
    end.


cas_value(16#00) ->
    undefined;
cas_value(undefined) ->
    16#00;
cas_value(Value) when is_integer(Value) andalso Value > 0 ->
    Value.

%% 0-1 Request ID
%% 2-3 Sequence number
%% 4-5 Total number of datagrams in this message
%% 6-7 Reserved for future use; must be 0
receive_udp_response(Socket, Id, Timeout) ->
    case gen_udp:recv(Socket, 0, Timeout) of
        {ok, {_, _, <<Id:16, Seq:16, D:16, 0:16, Data/binary>>}} ->
            receive_udp_response(Socket, Id, Timeout ,D, gb_trees:enter(Seq, Data, gb_trees:empty()));
        {error, Reason} ->
            throw({failed, {receive_bytes, Reason}});
        Datagram ->
            throw({failed, {receive_bytes, {unexpected_datagram, Datagram}}})
    end.

receive_udp_response(Socket, Id, Timeout, NumberOfDatagrams, Datagrams) ->
    case gb_trees:size(Datagrams) of
        NumberOfDatagrams ->
            iolist_to_binary(gb_trees:values(Datagrams));
        _ ->
            case gen_udp:recv(Socket, 0, Timeout) of
                {ok, {_, _, <<Id:16, Seq:16, NumberOfDatagrams:16, 0:16, Data/binary>>}} ->
                    receive_udp_response(Socket, Id, Timeout, NumberOfDatagrams, gb_trees:enter(Seq, Data, Datagrams));
                {error, Reason} ->
                    throw({failed, {receive_bytes, Reason}});
                Datagram ->
                    throw({failed, {receive_bytes, {unexpected_datagram, Datagram}}})
            end
    end.


receive_response(Client, Op, TimeLimit) ->
    Timeout = mero_conf:millis_to(TimeLimit),
    case receive_udp_response(Client#client.socket, Client#client.id, Timeout) of
        <<
          16#81:8,      % magic (0)
          Op:8,         % opcode (1)
          KeySize:16,   % key length (2,3)
          ExtrasSize:8, % extra length (4)
          _DT:8,        % data type (5)
          StatusCode:16,% status (6,7)
          BodySize:32,  % total body (8-11)
          _Opq:32,      % opaque (12-15)
          CAS:64,        % CAS (16-23)
          Body:BodySize/binary
        >> ->
            case Body of
                <<_Extras:ExtrasSize/binary, Key:KeySize/binary, Value/binary>> -> 
                    case response_status(StatusCode) of
                        ok ->
                            #mero_item{key = Key, value = Value, cas = cas_value(CAS)};
                        {error, not_found} ->
                            #mero_item{key = Key, cas = cas_value(CAS)};
                        Error ->
                            Error
                    end;
                Data ->
                    throw({failed, {unexpected_body, Data}})
            end;
        Data ->
            throw({failed, {unexpected_header, Data, {expected, Op}}})
    end.



async_mget(Client, Keys) ->
    try
        {ok, send_gets(Client, Keys)}
    catch
        throw:{failed, Reason} ->
            {error, Reason}
    end.


multipack([Item], _QuietOp, NoisyOp) ->
    [pack({NoisyOp, Item})];
multipack([Item|Rest], QuietOp, NoisyOp) ->
    [pack({QuietOp, Item}) | multipack(Rest, QuietOp, NoisyOp)].

send_quietly_butlast(Client, Items, QuietOp, NoisyOp) ->
    ok = send(Client, iolist_to_binary(multipack(Items, QuietOp, NoisyOp))).

send_gets(Client, Keys) ->
    send_quietly_butlast(Client, Keys, ?MEMCACHE_GETKQ, ?MEMCACHE_GETK).


async_mget_response(Client, Keys, TimeLimit) ->
    try
        Timeout = mero_conf:millis_to(TimeLimit),
        {ok, receive_mget_response(Client, Timeout, Keys, [])}
    catch
        throw:{failed, Reason} ->
            {error, Reason}
    end.

receive_mget_response(Client, Timeout, Keys, Acc) ->
    Resp =  receive_udp_response(Client#client.socket, Client#client.id, Timeout),
    do_receive_mget_response(Resp, Client, Timeout, Keys, Acc).

do_receive_mget_response(
        <<
          16#81:8,      % magic (0)
          Op:8,         % opcode (1)
          KeySize:16,   % key length (2,3)
          ExtrasSize:8, % extra length (4)
          _DT:8,        % data type (5)
          Status:16,    % status (6,7)
          BodySize:32,  % total body (8-11)
          _Opq:32,      % opaque (12-15)
          CAS:64,        % CAS (16-23)
          Body:BodySize/binary
        >>, Client, Timeout, Keys, Acc) ->
            case Body of
                <<_Extras:ExtrasSize/binary, Key:KeySize/binary, ValueReceived/binary>> ->
                    {Key, Value} = filter_by_status(Status, Op, Key, ValueReceived),
                    Responses = [#mero_item{key = Key, value = Value, cas = cas_value(CAS)}
                                 | Acc],
                    NKeys = lists:delete(Key, Keys),
                    case Op of
                        %% On silent we expect more values
                        ?MEMCACHE_GETKQ ->
                            receive_mget_response(Client, Timeout, NKeys, Responses);
                        %% This was the last one!
                        ?MEMCACHE_GETK ->
                            Responses ++ [#mero_item{key = KeyIn} || KeyIn <- NKeys]
                    end;
                Data ->
                    throw({failed, {unexpected_body, Data}})
            end;

do_receive_mget_response(Data, _, _, _, _) ->
    throw({failed, {unexpected_header, Data}}).

filter_by_status(?NO_ERROR,  _Op, Key, ValueReceived)  -> {Key, ValueReceived};
filter_by_status(?NOT_FOUND, _Op, Key, _ValueReceived) -> {Key, undefined};
filter_by_status(Status, _Op, _Key, _ValueReceived) -> throw({failed, {response_status, Status}}).




response_status(?NO_ERROR) -> ok;
response_status(?NOT_FOUND) -> {error, not_found};
response_status(?KEY_EXISTS) -> {error, already_exists};
response_status(?VALUE_TOO_LARGE) -> {error, value_too_large};
response_status(?INVALID_ARGUMENTS) -> {error, invalid_arguments};
response_status(?NOT_STORED) -> {error, not_stored};
response_status(?NON_NUMERIC_INCR) -> {error, incr_decr_on_non_numeric_value};
response_status(?UNKNOWN_COMMAND) -> {error, unknown_command};
response_status(?OOM) -> {error, out_of_memory};
response_status(StatusCode) -> throw({failed, {response_status, StatusCode}}).

incr_id(Client = #client{id = Id}) when Id < 64000 ->
    Client#client{id = Id +1};
incr_id(Client) ->
    Client#client{id = 0}.


