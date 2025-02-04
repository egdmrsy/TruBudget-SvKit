import { fromJS } from "immutable";

import {
  ADD_INITIAL_USER,
  ADD_TEMPORARY_GLOBAL_PERMISSION,
  CHANGE_USER_PASSWORD_SUCCESS,
  CHECK_USER_PASSWORD_ERROR,
  CHECK_USER_PASSWORD_SUCCESS,
  CLEAN_USER_ASSIGNMENTS,
  CREATE_GROUP_SUCCESS,
  DISABLE_USER,
  ENABLE_USER,
  FETCH_GROUPS_SUCCESS,
  FETCH_USER_ASSIGNMENTS_SUCCESS,
  GROUP_ID,
  GROUP_NAME,
  HIDE_DASHBOARD_DIALOG,
  HIDE_PASSWORD_DIALOG,
  LIST_GLOBAL_PERMISSIONS_SUCCESS,
  REMOVE_INITIAL_USER,
  REMOVE_TEMPORARY_GLOBAL_PERMISSION,
  RESET_USER,
  SET_DISPLAYNAME,
  SET_ORGANIZATION,
  SET_PASSWORD,
  SET_USERNAME,
  SET_USERNAME_INVALID,
  SHOW_DASHBOARD_DIALOG,
  SHOW_PASSWORD_DIALOG,
  STORE_NEW_PASSWORDS_MATCH,
  TAB_INDEX
} from "./actions";

const defaultState = fromJS({
  tabIndex: 0,
  dashboardDialogShown: false,
  passwordDialogShown: false,
  userToAdd: {
    username: "",
    password: "",
    organization: "",
    displayName: ""
  },
  globalPermissions: {},
  temporaryGlobalPermissions: {},
  editId: "",
  dialogType: "",
  groups: [],
  userAssignments: {},
  editDialogShown: false,
  groupToAdd: {
    groupId: "",
    name: "",
    groupUsers: []
  },
  userPassword: "",
  newPassword: "",
  newPasswordConfirmation: "",
  newPasswordsMatch: true,
  usernameInvalid: false
});

export default function userDashboardReducer(state = defaultState, action) {
  switch (action.type) {
    case FETCH_GROUPS_SUCCESS:
      return state.set("groups", fromJS(action.groups));
    case FETCH_USER_ASSIGNMENTS_SUCCESS:
      return state.set("userAssignments", fromJS(action.userAssignments));
    case CLEAN_USER_ASSIGNMENTS:
      return state.set("userAssignments", defaultState.get("userAssignments"));
    case GROUP_ID:
      return state.setIn(["groupToAdd", "groupId"], action.groupId);
    case GROUP_NAME:
      return state.setIn(["groupToAdd", "name"], action.name);
    case ADD_INITIAL_USER:
      return state.updateIn(["groupToAdd", "groupUsers"], (users) => [...users, action.userId]);
    case REMOVE_INITIAL_USER:
      // Offical way to delete something from an array with immutability https://redux.js.org/recipes/structuring-reducers/immutable-update-patterns
      return state.updateIn(["groupToAdd", "groupUsers"], (users) => [
        ...users.slice(0, users.indexOf(action.userId)),
        ...users.slice(users.indexOf(action.userId) + 1)
      ]);
    case CREATE_GROUP_SUCCESS:
      return state.set("groupToAdd", defaultState.get("groupToAdd"));
    case SET_ORGANIZATION:
      return state.setIn(["userToAdd", "organization"], action.organization);
    case SET_DISPLAYNAME:
      return state.setIn(["userToAdd", "displayName"], action.displayName);
    case SET_USERNAME:
      return state.setIn(["userToAdd", "username"], action.username);
    case SET_PASSWORD:
      return state.setIn(["userToAdd", "password"], action.password);
    case RESET_USER:
      return state.set("userToAdd", defaultState.get("userToAdd"));
    case TAB_INDEX:
      return state.set("tabIndex", action.value);
    case SHOW_DASHBOARD_DIALOG:
      return state.merge({
        dashboardDialogShown: true,
        dialogType: action.dialogType,
        editId: action.editId
      });
    case HIDE_DASHBOARD_DIALOG:
      return state.merge({
        dashboardDialogShown: false,
        userToAdd: defaultState.get("userToAdd"),
        authenticationFailed: false,
        globalPermissions: defaultState.get("globalPermissions"),
        temporaryGlobalPermissions: defaultState.get("temporaryGlobalPermissions")
      });
    case SHOW_PASSWORD_DIALOG:
      return state.merge({
        passwordDialogShown: true,
        editId: action.editId
      });
    case HIDE_PASSWORD_DIALOG:
      return state.merge({
        passwordDialogShown: false,
        authenticationFailed: false,
        editId: defaultState.get("editId")
      });

    case ENABLE_USER:
    case DISABLE_USER:
      return state.merge({
        editId: action.userId
      });

    case LIST_GLOBAL_PERMISSIONS_SUCCESS:
      return state.set("globalPermissions", fromJS(action.data)).set("temporaryGlobalPermissions", fromJS(action.data));
    case CHECK_USER_PASSWORD_SUCCESS:
      return state.set("authenticationFailed", false);
    case CHECK_USER_PASSWORD_ERROR:
      return state.set("authenticationFailed", true);
    case CHANGE_USER_PASSWORD_SUCCESS:
      return state.merge({
        passwordDialogShown: false,
        userToAdd: defaultState.get("userToAdd"),
        authenticationFailed: false
      });
    case STORE_NEW_PASSWORDS_MATCH:
      return state.set("newPasswordsMatch", action.newPasswordsMatch);
    case SET_USERNAME_INVALID:
      return state.set("usernameInvalid", action.usernameInvalid);
    case ADD_TEMPORARY_GLOBAL_PERMISSION:
      if (state.getIn(["temporaryGlobalPermissions", action.permission]) !== undefined) {
        return state.updateIn(["temporaryGlobalPermissions", action.permission], (users) => [...users, action.userId]);
      } else {
        return state.mergeIn(["temporaryGlobalPermissions"], { [action.permission]: [action.userId] });
      }
    case REMOVE_TEMPORARY_GLOBAL_PERMISSION:
      return state.updateIn(["temporaryGlobalPermissions", action.permission], (users) => [
        ...users.slice(0, users.indexOf(action.userId)),
        ...users.slice(users.indexOf(action.userId) + 1)
      ]);
    default:
      return state;
  }
}
