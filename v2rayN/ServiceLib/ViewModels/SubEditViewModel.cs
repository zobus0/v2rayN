namespace ServiceLib.ViewModels;

public class SubEditViewModel : MyReactiveObject
{
    [Reactive]
    public SubItem SelectedSource { get; set; }

    public ReactiveCommand<Unit, Unit> SaveCmd { get; }

    public SubEditViewModel(SubItem subItem, Func<EViewAction, object?, Task<bool>>? updateView)
    {
        _config = AppManager.Instance.Config;
        _updateView = updateView;

        SaveCmd = ReactiveCommand.CreateFromTask(async () =>
        {
            await SaveSubAsync();
        });

        SelectedSource = subItem.Id.IsNullOrEmpty() ? subItem : JsonUtils.DeepCopy(subItem);

        // Auto-fill a stable HWID so panels with an HWID device limit (e.g. Remnawave) count
        // this client as a single device. The value is persisted with the subscription.
        if (SelectedSource.Hwid.IsNullOrEmpty())
        {
            SelectedSource.Hwid = Utils.GetGuid();
        }
    }

    private async Task SaveSubAsync()
    {
        var remarks = SelectedSource.Remarks;
        if (remarks.IsNullOrEmpty())
        {
            NoticeManager.Instance.Enqueue(ResUI.PleaseFillRemarks);
            return;
        }

        var url = SelectedSource.Url;
        if (url.IsNotEmpty())
        {
            var uri = Utils.TryUri(url);
            if (uri == null)
            {
                NoticeManager.Instance.Enqueue(ResUI.InvalidUrlTip);
                return;
            }
            //Do not allow http protocol
            if (url.StartsWith(Global.HttpProtocol) && !Utils.IsPrivateNetwork(uri.IdnHost))
            {
                NoticeManager.Instance.Enqueue(ResUI.InsecureUrlProtocol);
                //return;
            }
        }

        if (await ConfigHandler.AddSubItem(_config, SelectedSource) == 0)
        {
            NoticeManager.Instance.Enqueue(ResUI.OperationSuccess);
            _updateView?.Invoke(EViewAction.CloseWindow, null);
        }
        else
        {
            NoticeManager.Instance.Enqueue(ResUI.OperationFailed);
        }
    }
}
