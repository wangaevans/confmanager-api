from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from netconfapp.serializers import ConfigurationSerializer, DeviceSerializer, LogSerializer
from .models import Device, Configuration, Log
from datetime import datetime
from django.utils.timezone import make_aware
from napalm import get_network_driver


@api_view(['GET'])
def show_configuration_logs(request):
    configuration_logs = Log.objects.order_by('-timestamp')
    data = [{'user': log.user.username, 'action': log.action, 'success': log.success,
             'details': log.details, 'timestamp': log.timestamp} for log in configuration_logs]
    serializer = LogSerializer(data, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def delete_item(request, pk):
    device = get_object_or_404(Device, pk=pk)
    try:
        device.delete()
        Log.objects.create(
            user=request.user, action=f'Delete device {device.username}', success=True)
        return Response(status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        Log.objects.create(
            user=request.user, action=f'Delete device {device.username}', success=False, details=str(e))
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def dashboard(request):
    devices = Device.objects.all()
    serializer = DeviceSerializer(devices, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def rollback_configuration(request, device_pk):
    device = get_object_or_404(Device, pk=device_pk)
    versions = Configuration.objects.filter(
        device=device).order_by('-timestamp')
    if request.method == 'POST':
        config_pk = request.POST.get('config_pk')
        if config_pk:
            configuration = get_object_or_404(Configuration, pk=config_pk)

            try:
                driver = get_network_driver(device.vendor)
                with driver(hostname=device.ip, username=device.username, password=device.password, optional_args={"port": device.port if device.port else 22, "transport": "ssh" if device.vendor != 'nxos' else 'telnet'}) as device_connection:
                    device_connection.open()
                    device_connection.load_merge_candidate(
                        config=configuration.updated_config)
                    device_connection.commit_config()
                    device_connection.close()

                device.default_configuration_version = configuration
                device.save()

                Log.objects.create(
                    user=request.user, action=f'Roll back to {configuration.version_tag} on {device.username}', success=True)
                return Response({'message': f'Rolled back to {configuration.version_tag} successfully.'}, status=status.HTTP_200_OK)
            except Exception as e:
                error_message = str(e)
                Log.objects.create(
                    user=request.user, action=f'Roll back to {configuration.version_tag} on {device.username}', success=False, details=error_message)
                return Response({'error': error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'Please select a version to rollback to.'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        data = {'device_id': device_pk, 'versions': [
            version.version_tag for version in versions]}
        return Response(data)


@api_view(['GET'])
def view_configurations(request, pk):
    device = get_object_or_404(Device, pk=pk)
    configurations = device.get_configurations()
    serializer = ConfigurationSerializer(configurations, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def view_devices_by_os(request):
    all_devices = Device.objects.all()
    cisco = all_devices.filter(vendor__in=['nxos', 'ios', 'iosxr'])
    aristas = all_devices.filter(vendor='eos')
    juniper = all_devices.filter(vendor='junos')
    data = {'cisco': cisco.values(), 'aristas': aristas.values(),
            'juniper': juniper.values()}
    return Response(data)


@api_view(['GET'])
def view_single_configuration(request, device_pk, config_pk):
    device = get_object_or_404(Device, pk=device_pk)
    configuration = get_object_or_404(Configuration, pk=config_pk)
    serializer = ConfigurationSerializer(configuration)
    return Response(serializer.data)


@api_view(['PUT'])
def modify_device_connection(request, pk):
    device = get_object_or_404(Device, pk=pk)
    data = request.data

    if data.get('ip') == device.ip and \
       data.get('username') == device.username and \
       data.get('password') == device.password and \
       data.get('vendor') == device.vendor and \
       data.get('port') == device.port:
        Log.objects.create(user=request.user, action=f'Modify connection details for device {device.username}',
                           success=False, details="The connection details were similar to the already existing connection")
    else:
        Log.objects.create(
            user=request.user, action=f'Modify connection details for device {device.username}', success=True)
        device.ip = data.get('ip', device.ip)
        device.username = data.get('username', device.username)
        device.password = data.get('password', device.password)
        device.vendor = data.get('vendor', device.vendor)
        device.port = data.get('port', device.port)
        device.save()

    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
def configure_device(request, pk):
    device = get_object_or_404(Device, pk=pk)
    data = request.data
    configuration = data.get('commands')
    user = request.user

    try:
        driver = get_network_driver(device.vendor)
        with driver(hostname=device.ip, username=device.username, password=device.password, optional_args={"port": device.port or 22, "transport": "ssh" if device.vendor != 'nxos' else 'telnet'}) as device_connection:
            device_connection.open()
            device_connection.load_merge_candidate(config=configuration)
            diff = device_connection.compare_config()

            if len(diff) > 0:
                device_connection.commit_config()
                updated_config = device_connection.get_config(
                    retrieve='running', sanitized=True)['running']
                device_connection.close()

                timestamp = make_aware(datetime.now())
                new_version_tag = f"v{device.configurations.count() + 1}"
                Configuration.objects.create(
                    device=device,
                    configuration=configuration,
                    version_tag=new_version_tag,
                    user=user,
                    timestamp=timestamp,
                    diff=diff,
                    updated_config=updated_config
                )

                return Response({'message': 'Configuration applied successfully.', 'version_tag': new_version_tag}, status=status.HTTP_200_OK)
            else:
                device_connection.discard_config()
                return Response({'message': 'No changes made.'}, status=status.HTTP_200_OK)
    except Exception as e:
        error_message = str(e)
        return Response({'error': error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def configure_multiple_devices(request):
    data = request.data
    selected_devices = data.get('devices', [])
    command_or_file = data.get('command_or_file')
    configuration = data.get('commands')
    config_file = data.get('config_file')
    user = request.user

    try:
        for device_pk in selected_devices:
            device = Device.objects.get(pk=device_pk)
            driver = get_network_driver(device.vendor)
            with driver(hostname=device.ip, username=device.username, password=device.password, optional_args={"port": device.port or 22, "transport": "ssh" if device.vendor != 'nxos' else 'telnet'}) as device_connection:
                device_connection.open()
                if command_or_file == 'command':
                    device_connection.load_merge_candidate(
                        config=configuration)
                elif command_or_file == 'file':
                    device_connection.load_merge_candidate(
                        filename=config_file)
                diff = device_connection.compare_config()
                if len(diff) > 0:
                    device_connection.commit_config()
                    updated_config = device_connection.get_config(
                        retrieve='running', sanitized=True)['running']
                    device_connection.close()
                    timestamp = make_aware(datetime.now())
                    new_version_tag = f"v{device.configurations.count() + 1}"
                    Configuration.objects.create(
                        device=device,
                        configuration=configuration,
                        version_tag=new_version_tag,
                        user=user,
                        timestamp=timestamp,
                        diff=diff,
                        updated_config=updated_config
                    )
                    Log.objects.create(
                        user=request.user, action=f'Configure {device.username}', success=True, details=f'A new configuration version ({new_version_tag}) has been applied successfully')
                else:
                    device_connection.discard_config()
                    Log.objects.create(
                        user=request.user, action=f'Configure {device.username}', success=False, details=f'No changes made on {device.username}. Configuration dropped!')
        return Response({'message': 'Configurations applied successfully'}, status=status.HTTP_200_OK)
    except Exception as e:
        error_message = str(e)
        Log.objects.create(
            user=request.user, action='Configure multiple devices', success=False, details=error_message)
        return Response({'error': error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def connect_to_device(request):
    '''
    function that connects the network device via SSH
    '''
    data = request.data
    ip = data['ip']
    username = data['username']
    password = data['password']
    vendor = data['os']
    # port = data.get('port')
    port = data.get('port', '22')

    try:
        device, created = Device.objects.get_or_create(
            ip=ip,
            defaults={'username': username, 'password': password,
                      'vendor': vendor, 'port': port}
        )

        driver = get_network_driver(vendor)
        try:
            with driver(hostname=device.ip, username=device.username, password=device.password, optional_args={"port": device.port if port else 22, "transport": "ssh" if vendor != 'nxos' else 'telnet'}) as device_connection:
                device_connection.open()
                device.save()
                device_connection.close()
                
                Log.objects.create(
                user=request.user, action=f'Create device {username}', success=True)
                return Response({'message': f'Device {username} created successfully.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            error_message = str(e)
            return Response({'Connection to device failed!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # return Response({'message': f'Device {username} created successfully.'}, status=status.HTTP_201_CREATED)
    except Exception as e:
        error_message = str(e)
        Log.objects.create(
            user=request.user, action=f'Create device {username}', success=False, details=error_message)
        return Response({'error': "Internal Server Error!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
