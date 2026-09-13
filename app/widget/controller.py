from typing import List

from fastapi import Depends, APIRouter

from app.db import Session, get_db
from app.auth import authorize
from .schema import WidgetSchema
from .service import WidgetService
from .model import Widget

router = APIRouter()


@router.get(
    "/",
    response_model=List[WidgetSchema],
    dependencies=[Depends(authorize("widget", "GET"))]
)
async def get_widget(session: Session = Depends(get_db)) -> List[Widget]:
    return await WidgetService.get_all(session)


@router.post(
    "/",
    response_model=WidgetSchema,
    dependencies=[Depends(authorize("widget", "POST"))]
)
async def post_widget(
    widget: WidgetSchema,
    session: Session = Depends(get_db),
) -> WidgetSchema:
    return await WidgetService.create(widget, session)


@router.get(
    "/<int:widget_id>",
    response_model=WidgetSchema,
    dependencies=[Depends(authorize("widget", "GET"))]
)
async def get_widget_by_id(
    widget_id: int,
    session: Session = Depends(get_db)
) -> Widget:
    return await WidgetService.get_by_id(widget_id, session)


@router.delete(
    "/<int:widget_id>",
    dependencies=[Depends(authorize("widget", "DELETE"))]
)
async def delete(
    widget_id: int,
    session: Session = Depends(get_db)
):
    _id = await WidgetService.delete_by_id(widget_id, session)
    return dict(status="Success", id=_id)


@router.put(
    "/<int:widget_id>",
    dependencies=[Depends(authorize("widget", "PUT"))]
)
async def put(
    widget: WidgetSchema,
    session: Session = Depends(get_db)
) -> WidgetSchema:
    cur_widget = session.query(Widget).get(widget.widget_id)
    return await WidgetService.update(cur_widget, widget, session)