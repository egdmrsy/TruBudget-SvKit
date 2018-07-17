import React, { Component } from "react";
import { connect } from "react-redux";

import { toggleSidebar } from "./actions";
import { logout } from "../Login/actions";

import FlyInNotifications from "../Notifications/FlyInNotifications";

import Navbar from "./Navbar";
import { toJS } from "../../helper";

class NavbarContainer extends Component {
  render() {
    return (
      <div>
        <Navbar
          {...this.props}
          unreadNotifications={this.props.notifications.reduce((acc, n) => (n.isRead ? acc : acc + 1), 0)}
        />
        <FlyInNotifications history={this.props.history} notifications={this.props.newNotifications} />
      </div>
    );
  }
}

const mapDispatchToProps = dispatch => {
  return {
    onToggleSidebar: () => dispatch(toggleSidebar()),
    logout: () => dispatch(logout())
  };
};

const mapStateToProps = state => {
  return {
    showSidebar: state.getIn(["navbar", "showSidebar"]),
    peers: state.getIn(["navbar", "peers"]),
    notifications: state.getIn(["notifications", "notifications"]),
    newNotifications: state.getIn(["notifications", "newNotifications"]),
    route: state.getIn(["route", "locationBeforeTransitions"]),
    streamNames: state.getIn(["navbar", "streamNames"]),
    displayName: state.getIn(["login", "displayName"]),
    organization: state.getIn(["login", "organization"]),
    avatar: state.getIn(["login", "avatar"]),
    environment: state.getIn(["login", "environment"]),
    avatarBackground: state.getIn(["login", "avatarBackground"]),
    currentProject: state.getIn(["navbar", "currentProject"]),
    currentSubProject: state.getIn(["navbar", "currentSubProject"]),
    allowedIntents: state.getIn(["login", "allowedIntents"])
  };
};

export default connect(mapStateToProps, mapDispatchToProps)(toJS(NavbarContainer));
