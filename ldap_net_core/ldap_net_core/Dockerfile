FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY ["ldap_net_core/ldap_net_core.csproj", "ldap_net_core/"]
RUN dotnet restore "ldap_net_core/ldap_net_core.csproj"
COPY . .
WORKDIR "/src/ldap_net_core"
RUN dotnet build "ldap_net_core.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "ldap_net_core.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "ldap_net_core.dll"]