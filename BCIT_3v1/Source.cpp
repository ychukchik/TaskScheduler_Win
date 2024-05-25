#include <iostream>
#include <atlbase.h>
#include <comdef.h> 
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

#include <netfw.h>
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#define WIDEN2(x) L ## x
#define WIDEN(x) WIDEN2(x)
#define __WFILE__ WIDEN(__FILE__)
#define HRCHECK(__expr) {hr=(__expr);if(FAILED(hr)){wprintf(L"FAILURE 0x%08X (%i)\n\tline: %u file: '%s'\n\texpr: '" WIDEN(#__expr) L"'\n",hr, hr, __LINE__,__WFILE__);goto cleanup;}}
#define RELEASE(__p) {if(__p!=nullptr){__p->Release();__p=nullptr;}}
#define STARTUP HRESULT hr=S_OK;
#define CLEANUP {cleanup:return hr;}

void Help(void);
HRESULT TaskList(void);
HRESULT DumpFolder(ITaskFolder*);
void BlockPing(const char*);
HRESULT WFCOMInitialize(INetFwPolicy2**);
int CreateTask(LPCWSTR, BSTR, BSTR, BSTR, BOOL, BSTR, BSTR);
int DeleteTask(LPCWSTR);

#define ARG_DEFENDER L"<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-Windows Defender/Operational\"><Select Path=\"Microsoft-Windows-Windows Defender/Operational\">*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID = 5007)]]</Select><Select Path=\"Microsoft-Windows-Windows Defender/WHC\">*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID = 5007)]]</Select></Query></QueryList>"
#define ARG_FIREWALL L"<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\"><Select Path=\"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\">*</Select></Query></QueryList>"
#define ARG_PING L"<QueryList><Query Id='1'><Select Path=\"Security\">*[System/EventID = 5152] and *[EventData[Data[@Name=\"SourceAddress\"] and Data=\"192.168.165.213\"]] </Select></Query></QueryList>"

void Help(void)
{
	std::cout << ">> help" << std::endl << std::endl;
	std::cout << "\"list\"              - list tasks;" << std::endl;
	std::cout << "\"changes\"           - Windows security changes;" << std::endl;
	std::cout << "\"block:<ip_address>\"- block ping requests from ip address;" << std::endl;
	std::cout << "\"help\"              - help information." << std::endl;
	return;
}

HRESULT TaskList(void)
{
	STARTUP;

	hr = CoInitialize(NULL);
	{
		CComPtr<ITaskService> svc;
		CComPtr<ITaskFolder> fld;
		HRCHECK(svc.CoCreateInstance(CLSID_TaskScheduler));
		HRCHECK(svc->Connect(CComVariant(), CComVariant(), CComVariant(), CComVariant()));
		HRCHECK(svc->GetFolder(CComBSTR(L"\\"), &fld));
		HRCHECK(DumpFolder(fld));
	}

	CoUninitialize();
	CLEANUP;
}

HRESULT DumpFolder(ITaskFolder* fld)
{
	STARTUP;
	CComPtr<IRegisteredTaskCollection> tasks;
	CComPtr<ITaskFolderCollection> children;
	LONG count;

	HRCHECK(fld->GetTasks(TASK_ENUM_HIDDEN, &tasks));
	HRCHECK(tasks->get_Count(&count));

	// dump out tasks
	for (LONG i = 1; i < (count + 1); i++)
	{
		CComPtr<IRegisteredTask> task;
		CComBSTR name;
		HRCHECK(tasks->get_Item(CComVariant(i), &task));
		HRCHECK(task->get_Name(&name));
		VARIANT_BOOL isEnabled = FALSE;
		task->get_Enabled(&isEnabled);
		wprintf(L"%s\n\t%s\n\n", name.m_str, isEnabled ? L"Enabled" : L"Disabled");
	}

	// dump out sub folder
	HRCHECK(fld->GetFolders(0, &children));
	HRCHECK(children->get_Count(&count));

	for (LONG i = 1; i < (count + 1); i++)
	{
		CComPtr<ITaskFolder> child;
		HRCHECK(children->get_Item(CComVariant(i), &child));

		// go recursive
		HRCHECK(DumpFolder(child));
	}

	CLEANUP;
}

void BlockPing(const char* ipAddr)
{
	_bstr_t bstrIpAddr(ipAddr);
	_bstr_t msg = L"\"Ping request from [" + bstrIpAddr + L"] has been blocked\"";

	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	INetFwPolicy2* pNetFwPolicy2 = NULL;
	INetFwRules* pFwRules = NULL;
	INetFwRule* pFwRule = NULL;

	BSTR bstrRuleName = SysAllocString(L"Echo request block");
	BSTR bstrRuleDescription = SysAllocString(L"Deny echo request");
	BSTR bstrRuleGroup = SysAllocString(L"");
	// ICMP Echo Request
	BSTR bstrICMPTypeCode = SysAllocString(L"8:*");

	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
	);

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
			goto Cleanup;
		}
	}

	// Retrieve INetFwPolicy2
	hr = WFCOMInitialize(&pNetFwPolicy2);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	// Retrieve INetFwRules
	hr = pNetFwPolicy2->get_Rules(&pFwRules);
	if (FAILED(hr))
	{
		printf("get_Rules failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Create a new Firewall Rule object.
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Populate the Firewall Rule object
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_Protocol(1);
	pFwRule->put_IcmpTypesAndCodes(bstrICMPTypeCode);
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
	pFwRule->put_Action(NET_FW_ACTION_BLOCK);
	pFwRule->put_RemoteAddresses(bstrIpAddr);
	pFwRule->put_Enabled(VARIANT_TRUE);

	// Add the Firewall Rule
	hr = pFwRules->Add(pFwRule);
	if (FAILED(hr))
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:

	// Free BSTR's
	SysFreeString(bstrRuleName);
	SysFreeString(bstrRuleDescription);
	SysFreeString(bstrRuleGroup);
	SysFreeString(bstrICMPTypeCode);

	// Release the INetFwRule object
	if (pFwRule != NULL)
	{
		pFwRule->Release();
	}

	// Release the INetFwRules object
	if (pFwRules != NULL)
	{
		pFwRules->Release();
	}

	// Release the INetFwPolicy2 object
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}

	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	return;
}

HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto Cleanup;
	}

Cleanup:
	return hr;
}

int CreateTask(LPCWSTR taskName, BSTR taskPath, BSTR query, BSTR args, BOOL putValueQueries, BSTR valueName, BSTR valueValue)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		printf("\nCoInitializeEx failed: %x", hr);
		return 1;
	}
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);
	if (FAILED(hr)) {
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return 1;
	}
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr)) {
		printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
		CoUninitialize();
		return 1;
	}
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr)) {
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t((BSTR)L"\\"), &pRootFolder);
	if (FAILED(hr)) {
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	pRootFolder->DeleteTask(_bstr_t(taskName), 0);
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	pService->Release();
	if (FAILED(hr)) {
		printf("Failed to create an instance of the task: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return 1;
	}
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr)) {
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	hr = pRegInfo->put_Author((BSTR)L"Bruh");
	pRegInfo->Release();
	if (FAILED(hr)) {
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	ITaskSettings* pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);

	if (FAILED(hr)) {
		printf("\nCannot get settings pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
	pSettings->Release();
	if (FAILED(hr)) {
		printf("\nCannot put setting info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr)) {
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_EVENT, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr)) {
		printf("\nCannot create the trigger: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	IEventTrigger* pEventTrigger = NULL;
	hr = pTrigger->QueryInterface(
		IID_IEventTrigger, (void**)&pEventTrigger);
	pTrigger->Release();
	if (FAILED(hr)) {
		printf("\nQueryInterface call on IEventTrigger failed: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	hr = pEventTrigger->put_Id(_bstr_t((BSTR)L"Trigger1"));
	if (FAILED(hr))
		printf("\nCannot put the trigger ID: %x", hr);
	hr = pEventTrigger->put_Subscription(query);
	if (FAILED(hr)) {
		printf("\nCannot put the event query: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	if (putValueQueries == TRUE) {
		ITaskNamedValueCollection* pValueQueries = NULL;
		pEventTrigger->get_ValueQueries(&pValueQueries);
		pValueQueries->Create(valueName, valueValue, NULL);
		hr = pEventTrigger->put_ValueQueries(pValueQueries);

		if (FAILED(hr)) {
			printf("\nCannot put value queries: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}
	}
	pEventTrigger->Release();
	IActionCollection* pActionCollection = NULL;
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr)) {
		printf("\nCannot get action collection pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	IAction* pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr)) {
		printf("\nCannot create an exec action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	IExecAction2* pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction2, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr)) {
		printf("\nQueryInterface call failed for IEmailAction: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	hr = pExecAction->put_Path(taskPath);
	if (FAILED(hr)) {
		printf("\nCannot put path information: %x", hr);
		pRootFolder->Release();
		pExecAction->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	hr = pExecAction->put_Arguments(args);
	if (FAILED(hr)) {
		printf("\nCannot put arguments information: %x", hr);
		pRootFolder->Release();
		pExecAction->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	pExecAction->Release();
	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(taskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(_bstr_t((BSTR)L"")),
		_variant_t(_bstr_t((BSTR)L"")),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t((BSTR)L""),
		&pRegisteredTask);
	if (FAILED(hr)) {
		printf("\nError saving the Task : %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}
	printf("Success\n");
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	CoUninitialize();
	return 0;
}

int DeleteTask(LPCWSTR taskName)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		printf("\nCoInitializeEx failed: %x", hr);
		return 1;
	}
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);
	if (FAILED(hr)) {
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return 1;
	}
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr)) {
		printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
		CoUninitialize();
		return 1;
	}
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr)) {
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t((BSTR)L"\\"), &pRootFolder);
	if (FAILED(hr)) {
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}
	pRootFolder->DeleteTask(_bstr_t(taskName), 0);
	printf("Deleted\n");
	pRootFolder->Release();
	CoUninitialize();
	return 0;
}

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		std::cout << "Error: Incorrect args" << std::endl;
		Help();
		system("pause");
		return 0;
	}

	if (!strncmp(argv[1], "list", strlen("list")))
	{
		HRESULT hr = TaskList();
	}
	else if (!strncmp(argv[1], "changes", strlen("changes")))
	{
		CreateTask((BSTR)L"A task for firewall",
			(BSTR)L"Z:\\BCIT_3_Message_v1\\x64\\Release\\BCIT_3_Message_v1.exe",
			(BSTR)ARG_FIREWALL,
			(BSTR)L"\"Firewall settings changed\"",
			FALSE,
			(BSTR)L"",
			(BSTR)L"");

		CreateTask(
			(BSTR)L"A task for defender",
			(BSTR)L"Z:\\BCIT_3_Message_v1\\x64\\Release\\BCIT_3_Message_v1.exe",
			(BSTR)ARG_DEFENDER,
			(BSTR)L"\"Defender settings changed\"",
			FALSE,
			(BSTR)L"",
			(BSTR)L"");

		CreateTask(
			(BSTR)L"A task for ping request",
			(BSTR)L"Z:\\BCIT_3_Message_v1\\x64\\Release\\BCIT_3_Message_v1.exe",
			(BSTR)ARG_PING,
			(BSTR)L"192.168.165.213",
			TRUE,
			(BSTR)L"srcIp",
			(BSTR)L"Event/EventData/Data[@Name='SourceAddress']");

		system("pause");

		DeleteTask((BSTR)L"A task for firewall");
		DeleteTask((BSTR)L"A task for defender");
		DeleteTask((BSTR)L"A task for ping request");
	}
	else if (!strncmp(argv[1], "block:", strlen("block:")))
	{
		const char* shift = strchr(argv[1], ':') + 1;
		if (!(*shift))
		{
			std::cout << "Wrong \"block\" parameter. Ask for help." << std::endl;
			return 0;
		}

		BlockPing(shift);
	}
	else if (!strncmp(argv[1], "help", strlen("help")))
	{
		Help();
	}
	else
	{
		std::cout << "Wrong argument." << std::endl << std::endl;
		Help();
	}

	return 0;
}

