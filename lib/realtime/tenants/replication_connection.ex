defmodule Realtime.Tenants.ReplicationConnection do
  @moduledoc """
  ReplicationConnection it's the module that provides a way to stream data from a PostgreSQL database using logical replication.

  ## Struct parameters
  * `connection_opts` - The connection options to connect to the database.
  * `table` - The table to replicate. If `:all` is passed, it will replicate all tables.
  * `schema` - The schema of the table to replicate. If not provided, it will use the `public` schema. If `:all` is passed, this option is ignored.
  * `opts` - The options to pass to this module
  * `step` - The current step of the replication process
  * `publication_name` - The name of the publication to create. If not provided, it will use the schema and table name.
  * `replication_slot_name` - The name of the replication slot to create. If not provided, it will use the schema and table name.
  * `output_plugin` - The output plugin to use. Default is `pgoutput`.
  * `proto_version` - The protocol version to use. Default is `1`.
  * `handler_module` - The module that will handle the data received from the replication stream.
  * `metadata` - The metadata to pass to the handler module.

  """
  use Postgrex.ReplicationConnection
  use Realtime.Logs

  import Realtime.Adapters.Postgres.Protocol
  import Realtime.Adapters.Postgres.Decoder

  alias Realtime.Adapters.Postgres.Decoder
  alias Realtime.Adapters.Postgres.Protocol.KeepAlive
  alias Realtime.Adapters.Postgres.Protocol.Write
  alias Realtime.Api.Tenant
  alias Realtime.Database
  alias Realtime.Tenants.BatchBroadcast
  alias Realtime.Tenants.Cache

  @type t :: %__MODULE__{
          tenant_id: String.t(),
          table: String.t(),
          schema: String.t(),
          opts: Keyword.t(),
          step:
            :disconnected
            | :check_replication_slot
            | :create_publication
            | :check_publication
            | :create_slot
            | :start_replication_slot
            | :streaming,
          publication_name: String.t(),
          replication_slot_name: String.t(),
          output_plugin: String.t(),
          proto_version: integer(),
          relations: map(),
          buffer: list(),
          monitored_pid: pid()
        }
  defstruct tenant_id: nil,
            table: nil,
            schema: "public",
            opts: [],
            step: :disconnected,
            publication_name: nil,
            replication_slot_name: nil,
            output_plugin: "pgoutput",
            proto_version: 1,
            relations: %{},
            buffer: [],
            monitored_pid: nil

  defmodule Wrapper do
    @moduledoc """
    This GenServer exists at the moment so that we can have an init timeout for ReplicationConnection
    """
    use GenServer

    def start_link(args, init_timeout) do
      GenServer.start_link(__MODULE__, args, timeout: init_timeout)
    end

    @impl true
    def init(args) do
      case Realtime.Tenants.ReplicationConnection.start_link(args) do
        {:ok, pid} -> {:ok, pid}
        {:error, reason} -> {:stop, reason}
      end
    end
  end

  @default_init_timeout 30_000

  @doc """
  Starts the replication connection for a tenant and monitors a given pid to stop the ReplicationConnection.
  """
  @spec start(Realtime.Api.Tenant.t(), pid()) :: {:ok, pid()} | {:error, any()}
  def start(tenant, monitored_pid, init_timeout \\ @default_init_timeout) do
    Logger.info("Starting replication for Broadcast Changes")
    opts = %__MODULE__{tenant_id: tenant.external_id, monitored_pid: monitored_pid}
    supervisor_spec = supervisor_spec(tenant)

    child_spec = %{
      id: __MODULE__,
      start: {Wrapper, :start_link, [opts, init_timeout]},
      restart: :transient,
      type: :worker
    }

    case DynamicSupervisor.start_child(supervisor_spec, child_spec) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, {:bad_return_from_init, {:stop, error, _}}} -> {:error, error}
      {:error, %Postgrex.Error{postgres: %{pg_code: "53300"}}} -> {:error, :max_wal_senders_reached}
      error -> error
    end
  end

  @doc """
  Finds replication connection by tenant_id
  """
  @spec whereis(String.t()) :: pid() | nil
  def whereis(tenant_id) do
    case Registry.lookup(Realtime.Registry.Unique, {__MODULE__, tenant_id}) do
      [{pid, _}] -> pid
      [] -> nil
    end
  end

  def start_link(%__MODULE__{tenant_id: tenant_id} = attrs) do
    tenant = Cache.get_tenant_by_external_id(tenant_id)
    connection_opts = Database.from_tenant(tenant, "realtime_broadcast_changes", :stop)

    connection_opts =
      [
        name: {:via, Registry, {Realtime.Registry.Unique, {__MODULE__, tenant_id}}},
        hostname: connection_opts.hostname,
        username: connection_opts.username,
        password: connection_opts.password,
        database: connection_opts.database,
        port: connection_opts.port,
        socket_options: connection_opts.socket_options,
        ssl: connection_opts.ssl,
        backoff_type: :stop,
        sync_connect: true,
        parameters: [
          application_name: "realtime_replication_connection"
        ]
      ]

    case Postgrex.ReplicationConnection.start_link(__MODULE__, attrs, connection_opts) do
      {:ok, pid} -> {:ok, pid}
      {:error, {:already_started, pid}} -> {:ok, pid}
      {:error, {:bad_return_from_init, {:stop, error}}} -> {:error, error}
      {:error, error} -> {:error, error}
    end
  end

  @impl true
  def init(%__MODULE__{tenant_id: tenant_id, monitored_pid: monitored_pid} = state) do
    Logger.metadata(external_id: tenant_id, project: tenant_id)
    Process.monitor(monitored_pid)
    state = %{state | table: "messages", schema: "realtime"}

    state = %{
      state
      | publication_name: publication_name(state),
        replication_slot_name: replication_slot_name(state)
    }

    Logger.info("Initializing connection with the status: #{inspect(state, pretty: true)}")

    {:ok, state}
  end

  @impl true
  def handle_connect(state) do
    replication_slot_name = replication_slot_name(state)
    Logger.info("Checking if replication slot #{replication_slot_name} exists")

    query =
      "SELECT * FROM pg_replication_slots WHERE slot_name = '#{replication_slot_name}'"

    {:query, query, %{state | step: :check_replication_slot}}
  end

  @impl true
  def handle_result([%Postgrex.Result{num_rows: 1}], %__MODULE__{step: :check_replication_slot}) do
    {:disconnect, {:shutdown, "Temporary Replication slot already exists and in use"}}
  end

  def handle_result(
        [%Postgrex.Result{num_rows: 0}],
        %__MODULE__{step: :check_replication_slot} = state
      ) do
    %__MODULE__{
      output_plugin: output_plugin,
      replication_slot_name: replication_slot_name,
      step: :check_replication_slot
    } = state

    Logger.info("Create replication slot #{replication_slot_name} using plugin #{output_plugin}")

    query =
      "CREATE_REPLICATION_SLOT #{replication_slot_name} TEMPORARY LOGICAL #{output_plugin} NOEXPORT_SNAPSHOT"

    {:query, query, %{state | step: :check_publication}}
  end

  def handle_result([%Postgrex.Result{}], %__MODULE__{step: :check_publication} = state) do
    %__MODULE__{table: table, schema: schema, publication_name: publication_name} = state

    Logger.info("Check publication #{publication_name} for table #{schema}.#{table} exists")
    query = "SELECT * FROM pg_publication WHERE pubname = '#{publication_name}'"

    {:query, query, %{state | step: :create_publication}}
  end

  def handle_result(
        [%Postgrex.Result{num_rows: 0}],
        %__MODULE__{step: :create_publication} = state
      ) do
    %__MODULE__{table: table, schema: schema, publication_name: publication_name} = state

    Logger.info("Create publication #{publication_name} for table #{schema}.#{table}")
    query = "CREATE PUBLICATION #{publication_name} FOR TABLE #{schema}.#{table}"

    {:query, query, %{state | step: :start_replication_slot}}
  end

  def handle_result(
        [%Postgrex.Result{num_rows: 1}],
        %__MODULE__{step: :create_publication} = state
      ) do
    {:query, "SELECT 1", %{state | step: :start_replication_slot}}
  end

  @impl true
  def handle_result(
        [%Postgrex.Result{}],
        %__MODULE__{step: :start_replication_slot} = state
      ) do
    %__MODULE__{
      proto_version: proto_version,
      replication_slot_name: replication_slot_name,
      publication_name: publication_name
    } = state

    Logger.info(
      "Starting stream replication for slot #{replication_slot_name} using publication #{publication_name} and protocol version #{proto_version}"
    )

    query =
      "START_REPLICATION SLOT #{replication_slot_name} LOGICAL 0/0 (proto_version '#{proto_version}', publication_names '#{publication_name}')"

    {:stream, query, [], %{state | step: :streaming}}
  end

  def handle_result(%Postgrex.Error{postgres: %{message: message}}, _state) do
    {:disconnect, "Error starting replication: #{message}"}
  end

  @impl true
  def handle_data(data, state) when is_keep_alive(data) do
    %KeepAlive{reply: reply, wal_end: wal_end} = parse(data)
    wal_end = wal_end + 1

    message =
      case reply do
        :now -> standby_status(wal_end, wal_end, wal_end, reply)
        :later -> hold()
      end

    {:noreply, message, state}
  end

  def handle_data(data, state) when is_write(data) do
    %Write{message: message} = parse(data)
    message |> decode_message() |> then(&send(self(), &1))
    {:noreply, [], state}
  end

  def handle_data(e, state) do
    log_error("UnexpectedMessageReceived", e)
    {:noreply, [], state}
  end

  @impl true
  def handle_info(%Decoder.Messages.Relation{} = msg, state) do
    %Decoder.Messages.Relation{id: id, namespace: namespace, name: name, columns: columns} = msg
    %{relations: relations} = state
    relation = %{name: name, columns: columns, namespace: namespace}
    relations = Map.put(relations, id, relation)
    {:noreply, %{state | relations: relations}}
  rescue
    e ->
      log_error("UnableToBroadcastChanges", e)
      {:noreply, state}
  catch
    e ->
      log_error("UnableToBroadcastChanges", e)
      {:noreply, state}
  end

  def handle_info(%Decoder.Messages.Insert{} = msg, state) do
    %Decoder.Messages.Insert{relation_id: relation_id, tuple_data: tuple_data} = msg
    %{relations: relations, tenant_id: tenant_id} = state

    case Map.get(relations, relation_id) do
      %{columns: columns} ->
        to_broadcast =
          tuple_data
          |> Tuple.to_list()
          |> Enum.zip(columns)
          |> Map.new(fn
            {nil, %{name: name}} -> {name, nil}
            {value, %{name: name, type: "jsonb"}} -> {name, Jason.decode!(value)}
            {value, %{name: name, type: "bool"}} -> {name, value == "t"}
            {value, %{name: name}} -> {name, value}
          end)

        payload = Map.get(to_broadcast, "payload")

        case payload do
          nil ->
            {:noreply, state}

          payload ->
            id = Map.fetch!(to_broadcast, "id")

            to_broadcast =
              %{
                topic: Map.fetch!(to_broadcast, "topic"),
                event: Map.fetch!(to_broadcast, "event"),
                private: Map.fetch!(to_broadcast, "private"),
                # Avoid overriding user provided id
                payload: Map.put_new(payload, "id", id)
              }

            %Tenant{} = tenant = Cache.get_tenant_by_external_id(tenant_id)

            case BatchBroadcast.broadcast(nil, tenant, %{messages: [to_broadcast]}, true) do
              :ok -> :ok
              error -> log_error("UnableToBatchBroadcastChanges", error)
            end

            {:noreply, state}
        end

      _ ->
        log_error("UnknownBroadcastChangesRelation", "Relation ID not found: #{relation_id}")
        {:noreply, state}
    end
  rescue
    e ->
      log_error("UnableToBroadcastChanges", e)
      {:noreply, state}
  catch
    e ->
      log_error("UnableToBroadcastChanges", e)
      {:noreply, state}
  end

  def handle_info({:DOWN, _, :process, _, _}, _), do: {:disconnect, :shutdown}
  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def handle_disconnect(state) do
    Logger.warning("Disconnecting broadcast changes handler in the step : #{inspect(state.step)}")
    {:noreply, %{state | step: :disconnected}}
  end

  @spec supervisor_spec(Tenant.t()) :: term()
  def supervisor_spec(%Tenant{external_id: tenant_id}) do
    {:via, PartitionSupervisor, {__MODULE__.DynamicSupervisor, tenant_id}}
  end

  def publication_name(%__MODULE__{table: table, schema: schema}) do
    "supabase_#{schema}_#{table}_publication"
  end

  def replication_slot_name(%__MODULE__{table: table, schema: schema}) do
    "supabase_#{schema}_#{table}_replication_slot_#{slot_suffix()}"
  end

  defp slot_suffix, do: Application.get_env(:realtime, :slot_name_suffix)
end
