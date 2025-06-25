defmodule RealtimeWeb.RealtimeChannel.BroadcastHandler do
  @moduledoc """
  Handles the Broadcast feature from Realtime
  """
  use Realtime.Logs

  import Phoenix.Socket, only: [assign: 3]

  alias RealtimeWeb.TenantBroadcaster
  alias Phoenix.Socket
  alias Realtime.Api.Tenant
  alias Realtime.GenCounter
  alias Realtime.RateCounter
  alias Realtime.Tenants.Authorization
  alias Realtime.Tenants.Authorization.Policies
  alias Realtime.Tenants.Authorization.Policies.BroadcastPolicies
  alias Realtime.Tenants.Cache
  
  require Logger

  @event_type "broadcast"
  @spec handle(map(), Socket.t()) :: {:reply, :ok, Socket.t()} | {:noreply, Socket.t()}
  def handle(payload, %{assigns: %{private?: false}} = socket) do 
    Logger.debug("[WS-RLS-DEBUG] 处理公共通道广播 - 租户: #{socket.assigns.tenant}, 主题: #{socket.assigns.tenant_topic}")
    handle(payload, nil, socket)
  end

  @spec handle(map(), pid() | nil, Socket.t()) :: {:reply, :ok, Socket.t()} | {:noreply, Socket.t()}
  def handle(payload, db_conn, %{assigns: %{private?: true}} = socket) do
    %{
      assigns: %{
        self_broadcast: self_broadcast,
        tenant_topic: tenant_topic,
        authorization_context: authorization_context,
        policies: policies,
        tenant: tenant_id
      }
    } = socket
    
    Logger.debug("[WS-RLS-DEBUG] 处理私有通道广播 - 租户: #{tenant_id}, 主题: #{tenant_topic}")

    case run_authorization_check(policies || %Policies{}, db_conn, authorization_context) do
      {:ok, %Policies{broadcast: %BroadcastPolicies{write: true}} = policies} ->
        Logger.debug("[WS-RLS-DEBUG] 广播写入权限检查通过 - 租户: #{tenant_id}, 主题: #{tenant_topic}")
        
        socket =
          socket
          |> assign(:policies, policies)
          |> increment_rate_counter()

        %{ack_broadcast: ack_broadcast} = socket.assigns
        send_message(tenant_id, self_broadcast, tenant_topic, payload)
        
        Logger.debug("[WS-RLS-DEBUG] 广播消息已发送 - 租户: #{tenant_id}, 主题: #{tenant_topic}, 自广播: #{self_broadcast}")
        
        if ack_broadcast, do: {:reply, :ok, socket}, else: {:noreply, socket}

      {:ok, policies} ->
        Logger.debug("[WS-RLS-DEBUG] 广播写入权限检查失败 - 租户: #{tenant_id}, 主题: #{tenant_topic}, 策略: #{inspect(policies)}")
        {:noreply, assign(socket, :policies, policies)}

      {:error, :rls_policy_error, error} ->
        Logger.debug("[WS-RLS-DEBUG] 广播写入权限检查错误 - RLS策略错误: #{inspect(error)}")
        log_error("RlsPolicyError", error)
        {:noreply, socket}

      {:error, error} ->
        Logger.debug("[WS-RLS-DEBUG] 广播写入权限检查错误 - 错误: #{inspect(error)}")
        log_error("UnableToSetPolicies", error)
        {:noreply, socket}
    end
  end

  def handle(payload, _db_conn, %{assigns: %{private?: false}} = socket) do
    %{
      assigns: %{
        tenant_topic: tenant_topic,
        self_broadcast: self_broadcast,
        ack_broadcast: ack_broadcast,
        tenant: tenant_id
      }
    } = socket
    
    Logger.debug("[WS-RLS-DEBUG] 处理公共通道广播(无数据库连接) - 租户: #{tenant_id}, 主题: #{tenant_topic}")

    socket = increment_rate_counter(socket)
    send_message(tenant_id, self_broadcast, tenant_topic, payload)
    
    Logger.debug("[WS-RLS-DEBUG] 公共通道广播消息已发送 - 租户: #{tenant_id}, 主题: #{tenant_topic}, 自广播: #{self_broadcast}")

    if ack_broadcast,
      do: {:reply, :ok, socket},
      else: {:noreply, socket}
  end

  defp send_message(tenant_id, self_broadcast, tenant_topic, payload) do
    with %Tenant{} = tenant <- Cache.get_tenant_by_external_id(tenant_id) do
      if self_broadcast do
        Logger.debug("[WS-RLS-DEBUG] 发送广播(包含自己) - 租户: #{tenant_id}, 主题: #{tenant_topic}")
        TenantBroadcaster.broadcast(tenant, tenant_topic, @event_type, payload)
      else
        Logger.debug("[WS-RLS-DEBUG] 发送广播(不包含自己) - 租户: #{tenant_id}, 主题: #{tenant_topic}")
        TenantBroadcaster.broadcast_from(tenant, self(), tenant_topic, @event_type, payload)
      end
    end
  end

  defp increment_rate_counter(%{assigns: %{policies: %Policies{broadcast: %BroadcastPolicies{write: false}}}} = socket) do
    Logger.debug("[WS-RLS-DEBUG] 跳过速率计数器增加 - 无广播写入权限")
    socket
  end

  defp increment_rate_counter(%{assigns: %{rate_counter: counter}} = socket) do
    Logger.debug("[WS-RLS-DEBUG] 增加速率计数器 - 计数器ID: #{counter.id}")
    GenCounter.add(counter.id)
    {:ok, rate_counter} = RateCounter.get(counter.id)
    assign(socket, :rate_counter, rate_counter)
  end

  defp run_authorization_check(
         %Policies{broadcast: %BroadcastPolicies{write: nil}} = policies,
         db_conn,
         authorization_context
       ) do
    Logger.debug("[WS-RLS-DEBUG] 执行广播写入权限检查 - 租户: #{authorization_context.tenant_id}, 主题: #{authorization_context.topic}")
    Authorization.get_write_authorizations(policies, db_conn, authorization_context)
  end

  defp run_authorization_check(socket, _db_conn, _authorization_context) do
    Logger.debug("[WS-RLS-DEBUG] 跳过广播写入权限检查 - 策略已存在")
    {:ok, socket}
  end
end
