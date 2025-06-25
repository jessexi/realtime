defmodule RealtimeWeb.RealtimeChannel.PresenceHandler do
  @moduledoc """
  Handles the Presence feature from Realtime
  """
  use Realtime.Logs

  import Phoenix.Socket, only: [assign: 3]
  import Phoenix.Channel, only: [push: 3]

  alias Phoenix.Socket
  alias Phoenix.Tracker.Shard
  alias Realtime.GenCounter
  alias Realtime.RateCounter
  alias Realtime.Tenants.Authorization
  alias Realtime.Tenants.Authorization.Policies
  alias Realtime.Tenants.Authorization.Policies.PresencePolicies
  alias RealtimeWeb.Presence
  alias RealtimeWeb.RealtimeChannel.Logging
  
  require Logger

  @spec handle(map(), Socket.t()) :: {:reply, :error | :ok, Socket.t()}
  def handle(payload, %{assigns: %{private?: false}} = socket) do
    Logger.debug("[WS-RLS-DEBUG] 处理公共通道在线状态 - 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")
    handle(payload, nil, socket)
  end

  @spec handle(map(), pid() | nil, Socket.t()) :: {:reply, :error | :ok, Socket.t()}
  def handle(%{"event" => event} = payload, db_conn, socket) do
    event = String.downcase(event, :ascii)
    
    Logger.debug("[WS-RLS-DEBUG] 处理在线状态事件 - 事件: #{event}, 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")

    case handle_presence_event(event, payload, db_conn, socket) do
      {:ok, socket} -> 
        Logger.debug("[WS-RLS-DEBUG] 在线状态事件处理成功 - 事件: #{event}")
        {:reply, :ok, socket}
      {:error, socket} -> 
        Logger.debug("[WS-RLS-DEBUG] 在线状态事件处理失败 - 事件: #{event}")
        {:reply, :error, socket}
    end
  end

  def handle(_payload, _db_conn, socket), do: {:noreply, socket}

  @doc """
  Sends presence state to connected clients
  """
  @spec sync(Socket.t()) :: {:noreply, Socket.t()}
  def sync(%{assigns: %{private?: false}} = socket) do
    %{assigns: %{tenant_topic: topic, tenant: tenant_id}} = socket
    Logger.debug("[WS-RLS-DEBUG] 同步公共通道在线状态 - 租户: #{tenant_id}, 主题: #{topic}")
    
    socket = count(socket)
    push(socket, "presence_state", presence_dirty_list(topic))
    {:noreply, socket}
  end

  def sync(%{assigns: assigns} = socket) do
    %{tenant_topic: topic, policies: policies, tenant: tenant_id} = assigns
    
    Logger.debug("[WS-RLS-DEBUG] 同步私有通道在线状态 - 租户: #{tenant_id}, 主题: #{topic}, 策略: #{inspect(policies)}")

    socket =
      case policies do
        %Policies{presence: %PresencePolicies{read: false}} ->
          Logger.debug("[WS-RLS-DEBUG] 在线状态同步被忽略 - 无读取权限, 主题: #{topic}")
          socket

        _ ->
          socket = Logging.maybe_log_handle_info(socket, :sync_presence)
          Logger.debug("[WS-RLS-DEBUG] 发送在线状态 - 主题: #{topic}")
          push(socket, "presence_state", presence_dirty_list(topic))
          socket
      end

    {:noreply, socket}
  end

  defp handle_presence_event("track", payload, _db_conn, %{assigns: %{private?: false}} = socket) do
    Logger.debug("[WS-RLS-DEBUG] 处理公共通道track事件 - 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")
    track(socket, payload)
  end

  defp handle_presence_event(
         "track",
         payload,
         db_conn,
         %{assigns: %{private?: true, policies: %Policies{presence: %PresencePolicies{write: nil}} = policies}} = socket
       ) do
    %{assigns: %{authorization_context: authorization_context, tenant: tenant_id, tenant_topic: topic}} = socket
    
    Logger.debug("[WS-RLS-DEBUG] 检查私有通道track事件写入权限 - 租户: #{tenant_id}, 主题: #{topic}")

    case Authorization.get_write_authorizations(policies, db_conn, authorization_context) do
      {:ok, policies} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态写入权限检查成功 - 策略: #{inspect(policies)}")
        socket = assign(socket, :policies, policies)
        handle_presence_event("track", payload, db_conn, socket)

      {:error, :rls_policy_error, error} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态写入权限检查失败 - RLS策略错误: #{inspect(error)}")
        log_error("RlsPolicyError", error)
        {:error, socket}

      {:error, error} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态写入权限检查失败 - 错误: #{inspect(error)}")
        log_error("UnableToSetPolicies", error)
        {:error, socket}
    end
  end

  defp handle_presence_event(
         "track",
         payload,
         _db_conn,
         %{assigns: %{private?: true, policies: %Policies{presence: %PresencePolicies{write: true}}}} = socket
       ) do
    Logger.debug("[WS-RLS-DEBUG] 处理私有通道track事件(已有写入权限) - 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")
    track(socket, payload)
  end

  defp handle_presence_event(
         "track",
         _,
         _db_conn,
         %{assigns: %{private?: true, policies: %Policies{presence: %PresencePolicies{write: false}}}} = socket
       ) do
    Logger.debug("[WS-RLS-DEBUG] 拒绝私有通道track事件 - 无写入权限, 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")
    {:error, socket}
  end

  defp handle_presence_event("untrack", _, _, socket) do
    %{assigns: %{presence_key: presence_key, tenant_topic: tenant_topic, tenant: tenant_id}} = socket
    Logger.debug("[WS-RLS-DEBUG] 处理untrack事件 - 租户: #{tenant_id}, 主题: #{tenant_topic}, 键: #{presence_key}")
    {Presence.untrack(self(), tenant_topic, presence_key), socket}
  end

  defp handle_presence_event(event, _, _, socket) do
    Logger.debug("[WS-RLS-DEBUG] 未知在线状态事件 - 事件: #{event}, 租户: #{socket.assigns.tenant}")
    log_error("UnknownPresenceEvent", event)
    {:error, socket}
  end

  defp track(socket, payload) do
    %{assigns: %{presence_key: presence_key, tenant_topic: tenant_topic, tenant: tenant_id}} = socket
    payload = Map.get(payload, "payload", %{})
    
    Logger.debug("[WS-RLS-DEBUG] 跟踪在线状态 - 租户: #{tenant_id}, 主题: #{tenant_topic}, 键: #{presence_key}")

    case Presence.track(self(), tenant_topic, presence_key, payload) do
      {:ok, _} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态跟踪成功 - 主题: #{tenant_topic}, 键: #{presence_key}")
        {:ok, socket}

      {:error, {:already_tracked, pid, _, _}} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态已跟踪，尝试更新 - 主题: #{tenant_topic}, 键: #{presence_key}")
        case Presence.update(pid, tenant_topic, presence_key, payload) do
          {:ok, _} -> 
            Logger.debug("[WS-RLS-DEBUG] 在线状态更新成功 - 主题: #{tenant_topic}, 键: #{presence_key}")
            {:ok, socket}
          {:error, error} -> 
            Logger.debug("[WS-RLS-DEBUG] 在线状态更新失败 - 错误: #{inspect(error)}")
            {:error, socket}
        end

      {:error, error} ->
        Logger.debug("[WS-RLS-DEBUG] 在线状态跟踪失败 - 错误: #{inspect(error)}")
        log_error("UnableToTrackPresence", error)
        {:error, socket}
    end
  end

  defp count(%{assigns: %{presence_rate_counter: presence_counter}} = socket) do
    Logger.debug("[WS-RLS-DEBUG] 增加在线状态计数器 - 计数器ID: #{inspect(presence_counter.id)}")
    GenCounter.add(presence_counter.id)
    {:ok, presence_rate_counter} = RateCounter.get(presence_counter.id)

    assign(socket, :presence_rate_counter, presence_rate_counter)
  end

  defp presence_dirty_list(topic) do
    [{:pool_size, size}] = :ets.lookup(Presence, :pool_size)
    
    Logger.debug("[WS-RLS-DEBUG] 获取在线状态列表 - 主题: #{topic}, 池大小: #{size}")

    Presence
    |> Shard.name_for_topic(topic, size)
    |> Shard.dirty_list(topic)
    |> Phoenix.Presence.group()
  end
end
