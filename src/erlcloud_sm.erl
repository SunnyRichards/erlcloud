-module(erlcloud_sm).
-author("joshua@halloapp.com").

-include("erlcloud.hrl").
-include("erlcloud_aws.hrl").

%%% Library initialization.
-export([new/2, new/3, new/4]).

%%% API
-export([
    get_secret_value/2, get_secret_value/3,
    describe_secret/1, describe_secret/2,
    list_all_secrets/0, list_all_secrets/1, list_all_secrets/2,
    list_secret_version_ids/2, list_secret_version_ids/3,
    delete_secret/2,  delete_secret/3,
    restore_secret/1,  restore_secret/2,
    update_secret/2
    ]).

%%%------------------------------------------------------------------------------
%%% Shared types
%%%------------------------------------------------------------------------------

-type sm_response() :: {ok, proplists:proplist()} | {error, term()}.

-type get_secret_value_option() :: {version_id | version_stage, binary()}.
-type get_secret_value_options() :: [get_secret_value_option()].

%%%------------------------------------------------------------------------------
%%% Library initialization.
%%%------------------------------------------------------------------------------

-spec new(string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey) ->
    #aws_config{
        access_key_id = AccessKeyID,
        secret_access_key = SecretAccessKey
    }.


-spec new(string(), string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{
        access_key_id = AccessKeyID,
        secret_access_key = SecretAccessKey,
        sm_host = Host
    }.


-spec new(string(), string(), string(), non_neg_integer()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #aws_config{
        access_key_id = AccessKeyID,
        secret_access_key = SecretAccessKey,
        sm_host = Host,
        sm_port = Port
    }.

%%------------------------------------------------------------------------------
%% GetSecretValue
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html]
%% @end
%%------------------------------------------------------------------------------

-spec get_secret_value(SecretId :: binary(), Opts :: get_secret_value_options()) -> sm_response().
get_secret_value(SecretId, Opts) ->
    get_secret_value(SecretId, Opts, erlcloud_aws:default_config()).


-spec get_secret_value(SecretId :: binary(), Opts :: get_secret_value_options(),
        Config :: aws_config()) -> sm_response().
get_secret_value(SecretId, Opts, Config) ->
    Json = lists:map(
        fun
            ({version_id, Val}) -> {<<"VersionId">>, Val};
            ({version_stage, Val}) -> {<<"VersionStage">>, Val};
            (Other) -> Other
        end,
        [{<<"SecretId">>, SecretId} | Opts]),
    sm_request(Config, "secretsmanager.GetSecretValue", Json).

%%------------------------------------------------------------------------------
%% DescribeSecrets
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html]
%% @end
%%------------------------------------------------------------------------------

-spec describe_secret(SecretId :: binary()) -> sm_response().
describe_secret(SecretId) ->
    describe_secret(SecretId, erlcloud_aws:default_config()).

-spec describe_secret(SecretId :: binary(), Config :: aws_config()) -> sm_response().
describe_secret(SecretId, Config) ->
    Json = #{<<"SecretId">> => SecretId},
    sm_request(Config, "secretsmanager.DescribeSecret", Json).

%%------------------------------------------------------------------------------
%% ListSecrets
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html]
%% @end
%%------------------------------------------------------------------------------

-spec list_all_secrets() -> sm_response().
list_all_secrets() ->
    list_all_secrets(#{}, erlcloud_aws:default_config()).

-spec list_all_secrets(Filters :: map()) -> sm_response().
list_all_secrets(Filters) ->
    list_all_secrets(Filters, erlcloud_aws:default_config()).

-spec list_all_secrets(Filters :: map(), Config :: aws_config()) -> sm_response().
list_all_secrets(Filters, Config) ->
    Json = lists:map(
        fun
            ({filters, Val}) -> {<<"Filters">>, Val};
            ({max_results, Val}) -> {<<"MaxResults">>, Val};
            ({next_token, Val}) -> {<<"NextToken">>, Val};
            ({sort_order, Val}) -> {<<"SortOrder">>, Val};

            (Other) -> Other
        end, [Filters]),
    sm_request(Config, "secretsmanager.ListSecrets", Json).

%%------------------------------------------------------------------------------
%% ListSecretVersionIds
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecretVersionIds.html]
%% @end
%%------------------------------------------------------------------------------

-spec list_secret_version_ids(SecretId :: binary(), Opts :: get_secret_value_options()) -> sm_response().
list_secret_version_ids(SecretId, Opts) ->
    list_secret_version_ids(SecretId, Opts, erlcloud_aws:default_config()).

-spec list_secret_version_ids(SecretId :: binary(), Opts :: get_secret_value_options(),
    Config :: aws_config()) -> sm_response().
list_secret_version_ids(SecretId, Opts, Config) ->
    Json = lists:map(
        fun
            ({max_results, Val}) -> {<<"MaxResults">>, Val};
            ({next_token, Val}) -> {<<"NextToken">>, Val};
            ({sort_order, Val}) -> {<<"SortOrder">>, Val};
            (Other) -> Other
        end,
        [{<<"SecretId">>, SecretId} | Opts]),
    sm_request(Config, "secretsmanager.ListSecretVersionIds", Json).

%%------------------------------------------------------------------------------
%% DeleteSecret
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html]
%% @end
%%------------------------------------------------------------------------------

-spec delete_secret(SecretId :: binary(), Opts :: get_secret_value_options()) -> sm_response().
delete_secret(SecretId, Opts) ->
    get_secret_value(SecretId, Opts, erlcloud_aws:default_config()).


-spec delete_secret(SecretId :: binary(), Opts :: get_secret_value_options(),
    Config :: aws_config()) -> sm_response().
delete_secret(SecretId, Opts, Config) ->
    Json = lists:map(
        fun
            ({force_delete, Val}) -> {<<"ForceDeleteWithoutRecovery">>, Val};
            ({recovery_window, Val}) -> {<<"RecoveryWindowInDays">>, Val};
            (Other) -> Other
        end,
        [{<<"SecretId">>, SecretId} | Opts]),
    sm_request(Config, "secretsmanager.DeleteSecret", Json).

%%------------------------------------------------------------------------------
%% RestoreSecret
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_RestoreSecret.html]
%% @end
%%------------------------------------------------------------------------------

-spec restore_secret(SecretId :: binary()) -> sm_response().
restore_secret(SecretId) ->
    get_secret_value(SecretId, erlcloud_aws:default_config()).


-spec restore_secret(SecretId :: binary(), Config :: aws_config()) -> sm_response().
restore_secret(SecretId, Config) ->
    Json = #{<<"SecretId">> => SecretId},
    sm_request(Config, "secretsmanager.RestoreSecret", Json).

%%------------------------------------------------------------------------------
%% UpdateSecret
%%------------------------------------------------------------------------------
%% @doc
%% SM API:
%% [https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecret.html]
%% @end
%%------------------------------------------------------------------------------

-spec update_secret(SecretId :: binary(), Opts :: get_secret_value_options()) -> sm_response().
update_secret(SecretId, Opts) ->
    update_secret(SecretId, Opts, erlcloud_aws:default_config()).

-spec update_secret(SecretId :: binary(), Opts :: get_secret_value_options(),
    Config :: aws_config()) -> sm_response().
update_secret(SecretId, Opts, Config) ->
    Json = lists:map(
        fun
            ({kms_key_id, Val}) -> {<<"KmsKeyId">>, Val};
            ({description, Val}) -> {<<"Description">>, Val};
            ({secret_bin, Val}) -> {<<"SecretBinary">>, Val};
            ({secret_string, Val}) -> {<<"SecretString">>, Val};
            ({request_token, Val}) -> {<<"ClientRequestToken">>, Val};
            (Other) -> Other
        end,
        [{<<"SecretId">>, SecretId} | Opts]),
    sm_request(Config, "secretsmanager.UpdateSecret", Json).

%%%------------------------------------------------------------------------------
%%% Internal Functions
%%%------------------------------------------------------------------------------

sm_request(Config, Operation, Body) ->
    case erlcloud_aws:update_config(Config) of
        {ok, Config1} ->
            sm_request_no_update(Config1, Operation, Body);
        {error, Reason} ->
            {error, Reason}
    end.

sm_request_no_update(Config, Operation, [#{}]) ->
    sm_request_no_update(Config, Operation, #{});
sm_request_no_update(Config, Operation, Body) ->
    Payload = jsx:encode(Body),
    Headers = headers(Config, Operation, Payload),
    Request = #aws_request{service = sm,
        uri = uri(Config),
        method = post,
        request_headers = Headers,
        request_body = Payload},
    case erlcloud_aws:request_to_return(erlcloud_retry:request(Config, Request, fun sm_result_fun/1)) of
        {ok, {_RespHeaders, <<>>}} -> {ok, []};
        {ok, {_RespHeaders, RespBody}} -> {ok, jsx:decode(RespBody, [{return_maps, false}])};
        {error, _} = Error -> Error
    end.


headers(Config, Operation, Body) ->
    Headers = [{"host", Config#aws_config.sm_host},
        {"x-amz-target", Operation},
        {"content-type", "application/x-amz-json-1.1"}],
    Region = erlcloud_aws:aws_region_from_host(Config#aws_config.sm_host),
    erlcloud_aws:sign_v4_headers(Config, Headers, Body, Region, "secretsmanager").


uri(#aws_config{sm_scheme = Scheme, sm_host = Host} = Config) ->
    lists:flatten([Scheme, Host, port_spec(Config)]).


port_spec(#aws_config{sm_port = 443}) ->
    "";
port_spec(#aws_config{sm_port = Port}) ->
    [":", erlang:integer_to_list(Port)].


-spec sm_result_fun(Request :: aws_request()) -> aws_request().
sm_result_fun(#aws_request{response_type = ok} = Request) ->
    Request;
sm_result_fun(#aws_request{response_type = error,
        error_type = aws, response_status = Status} = Request) when Status >= 500 ->
    Request#aws_request{should_retry = true};
sm_result_fun(#aws_request{response_type = error, error_type = aws} = Request) ->
    Request#aws_request{should_retry = false}.

