from rest_framework import mixins, viewsets
from rest_framework.viewsets import GenericViewSet


class CreateViewSet(mixins.CreateModelMixin, GenericViewSet):
    pass


class ListCreateViewSet(mixins.CreateModelMixin,mixins.ListModelMixin, GenericViewSet):
    pass


class ListViewSet(mixins.ListModelMixin, GenericViewSet):
    pass


class FetchUpdateViewSets(viewsets.ReadOnlyModelViewSet,mixins.UpdateModelMixin, GenericViewSet):
    http_method_names = ['get', 'post', 'put', 'delete', 'head', 'options', 'trace']




